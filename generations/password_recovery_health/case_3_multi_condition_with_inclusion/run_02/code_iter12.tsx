
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: secure in-memory sessions, CSRF, throttling, Argon2id, and short-lived reset records. */
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
const RESERVATION_MS = 2 * 60 * 1000;
const BODY_LIMIT = 8192;
const RESET_FAILURE_LIMIT = 5;
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
    id: randomToken(), csrf: randomToken(), expiresAt: now() + SESSION_MS,
    recovery: null, mfa: null, authenticatedAccount: null,
    privacyAccepted: false, appointmentBooked: false,
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
  for (const [id, session] of sessions) if (session.expiresAt <= now()) sessions.delete(id);
  for (const [hash, record] of resetTokens) {
    if (record.reserved && record.reservedAt < now() - RESERVATION_MS) {
      record.reserved = false;
      record.reservationId = "";
      record.reservedAt = 0;
    }
    if (record.expiresAt <= now() || (record.used && record.usedAt < now() - RESET_MS)) resetTokens.delete(hash);
  }
  for (const [key, tries] of recoveryIssues) {
    const valid = tries.filter(time => time > now() - RESET_MS);
    if (valid.length) recoveryIssues.set(key, valid); else recoveryIssues.delete(key);
  }
  for (const [key, value] of loginFailures) if (value.lockUntil && value.lockUntil <= now()) loginFailures.delete(key);
}
setInterval(clean, 60_000);

function headers(nonce = "") {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": nonce ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'` : "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin", "Cache-Control": "no-store, max-age=0, must-revalidate", "Pragma": "no-cache",
  };
}
function respond(body: string, status: number, type: string, nonce = "", extra: Record<string, string> = {}) {
  return new Response(body, { status, headers: { ...headers(nonce), "Content-Type": type, ...extra } });
}
function json(value: any, status = 200) { return respond(JSON.stringify(value), status, "application/json; charset=utf-8"); }
function error(message: string, status = 400) { return json({ ok: false, message }, status); }
function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}

/* Requirement 1: bounded parsing of untrusted request bodies. */
async function body(request: Request) {
  if (!request.body) return {};
  const reader = request.body.getReader(), chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      received += part.value.byteLength;
      if (received > BODY_LIMIT) { await reader.cancel(); throw new Error("too large"); }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(Buffer.concat(chunks.map(v => Buffer.from(v)))));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch { throw new Error("invalid body"); }
}

/* Requirement 1: every state-changing request is same-origin and session-CSRF protected. */
function sensitive(request: Request) {
  const session = getSession(request);
  if (!session) return { failure: error("Please return to the secure portal and try again.", 401) };
  if (request.headers.get("origin") !== new URL(request.url).origin) return { failure: error("This request could not be confirmed safely. Please try again in the portal.", 403) };
  if (request.headers.get("x-csrf-token") !== session.csrf) return { failure: error("Your secure form check did not match. Refresh the page and try again.", 403) };
  return { session };
}
function identifier(value: unknown) {
  const text = typeof value === "string" ? value.trim().toLowerCase() : "";
  return /^[a-z0-9@._+\- ]{3,120}$/.test(text) ? text : "";
}
function passwordProblem(value: unknown) {
  if (typeof value !== "string") return "Enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  return /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value) ? "" : "Use an uppercase letter, lowercase letter, number, and symbol.";
}
function locked() { return error("For safety, please pause for five minutes before trying again.", 429); }
function issueAllowed(session: any, accountKey: string) {
  const key = `${session.id}:${accountKey}`, tries = (recoveryIssues.get(key) || []).filter(t => t > now() - RESET_MS);
  if (tries.length >= 3) return false;
  tries.push(now()); recoveryIssues.set(key, tries); return true;
}
function confirmationStatus(session: any) {
  const failures = session.resetConfirmationFailures;
  if (failures.lockUntil > now()) return "locked";
  if (failures.lockUntil) session.resetConfirmationFailures = { count: 0, lockUntil: 0 };
  return "open";
}
function confirmationFailure(session: any, message: string) {
  const failures = session.resetConfirmationFailures;
  if (++failures.count >= RESET_FAILURE_LIMIT) {
    failures.lockUntil = now() + LOCK_MS;
    return error("For safety, reset-token confirmation is paused for five minutes. You can return when ready.", 429);
  }
  return error(message);
}
function clearConfirmationFailures(session: any) { session.resetConfirmationFailures = { count: 0, lockUntil: 0 }; }

/* A reset token cannot be used while reserved by the atomic password replacement operation. */
function resetRecord(session: any) {
  const hash = session?.recovery?.tokenHash, record = hash && resetTokens.get(hash);
  return record && !record.used && !record.reserved && record.expiresAt > now() ? record : undefined;
}
function attachRecovery(session: any, tokenHash: string, record: any) {
  session.recovery = { tokenHash, stage: "identity", tokenConfirmed: true, identityVerified: false };
  record.lastAttachedAt = now();
}
async function findResetToken(value: unknown) {
  const token = typeof value === "string" ? value.trim() : "";
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(token)) return { token: "", hash: "", record: undefined };
  const hash = await digest(token);
  return { token, hash, record: resetTokens.get(hash) };
}
function invalidRecord(record: any) { return !record || record.used || record.reserved || record.expiresAt <= now(); }

async function recoveryRequest(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Please enter your account details in the form."); }
  const id = identifier(input.identifier);
  if (!id) return error("Enter an email address or account reference using letters, numbers, and common punctuation.");
  const accountKey = await digest(id), authorized = Boolean(accounts.get(accountKey)) && issueAllowed(check.session, accountKey);
  check.session.recovery = { stage: "instructionSent", tokenHash: "", tokenConfirmed: false, identityVerified: false };
  if (!authorized) return json({ ok: true, message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready." });

  const token = randomToken(), tokenHash = await digest(token), identityCode = mockCode(8);
  resetTokens.set(tokenHash, {
    accountKey, expiresAt: now() + RESET_MS, used: false, usedAt: 0, reserved: false, reservationId: "", reservedAt: 0,
    recoveryIdentityVerifier: await digest(identityCode), identityFailures: 0, identityLockUntil: 0,
  });
  check.session.recovery.tokenHash = tokenHash;
  return json({ ok: true, message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready.", deliveryPath: `/?recovery-test=${encodeURIComponent(token)}`, testValue: token, testIdentityValue: identityCode });
}

/* Recovery links remain non-mutating GETs; confirmation is a CSRF-protected POST. */
async function confirmInstruction(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  if (confirmationStatus(check.session) === "locked") return error("For safety, reset-token confirmation is paused for five minutes. You can return when ready.", 429);
  let input: any; try { input = await body(request); } catch { return confirmationFailure(check.session, "Enter the testing mock reset token."); }
  const found = await findResetToken(input.value);
  if (!found.token || !found.hash) return confirmationFailure(check.session, "That testing mock reset token is not in the expected format.");
  if (invalidRecord(found.record)) return confirmationFailure(check.session, "This reset instruction is invalid, expired, already used, or currently being completed. You can request a new one.");
  if (!equal(found.hash, await digest(found.token))) return confirmationFailure(check.session, "That testing mock reset token did not match.");
  attachRecovery(check.session, found.hash, found.record);
  clearConfirmationFailures(check.session);
  return json({ ok: true, message: "Testing mock reset token confirmed. Next, enter the separate recovery identity value." });
}
async function recoveryIdentity(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the separate recovery identity value."); }
  const recovery = check.session.recovery, record = resetRecord(check.session);
  if (!recovery?.tokenConfirmed || !record) return error("First confirm a current testing mock reset token.");
  if (record.identityLockUntil > now()) return locked();
  const value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  const verifier = /^[A-Z0-9_-]{6,20}$/.test(value) ? await digest(value) : "";
  if (!verifier || !equal(verifier, record.recoveryIdentityVerifier)) {
    if (++record.identityFailures >= 5) record.identityLockUntil = now() + LOCK_MS;
    return error(record.identityFailures >= 5 ? "For safety, please pause for five minutes, then request a fresh instruction." : "That separate recovery identity value did not match. Check the simulated delivery message and try again.");
  }
  recovery.identityVerified = true; recovery.stage = "identityVerified";
  return json({ ok: true, message: "Recovery identity value confirmed. Choose a new password when ready." });
}

/* Task: atomic token consumption. Reserve synchronously, hash asynchronously, then commit or safely release. */
async function replacePassword(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Please complete both password fields."); }
  const recovery = check.session.recovery;
  if (!recovery?.identityVerified) return error("Please complete a current recovery identity check before changing your password.");
  const problem = passwordProblem(input.password);
  if (problem) return error(problem);
  if (input.password !== input.confirmPassword) return error("The two passwords do not match yet.");

  const record = resetTokens.get(recovery.tokenHash);
  if (!record || record.used || record.reserved || record.expiresAt <= now()) return error("This recovery instruction is no longer available. Please request a new one.");
  const account = accounts.get(record.accountKey);
  if (!account) return error("This recovery instruction is no longer available. Please request a new one.");

  const reservationId = randomToken(18);
  record.reserved = true;
  record.reservationId = reservationId;
  record.reservedAt = now();

  try {
    const passwordHash = await Bun.password.hash(input.password, { algorithm: "argon2id" });
    const current = resetTokens.get(recovery.tokenHash);
    if (current !== record || !current.reserved || current.reservationId !== reservationId || current.used || current.expiresAt <= now()) {
      return error("This recovery instruction is no longer available. Please request a new one.");
    }
    account.passwordHash = passwordHash;
    current.used = true;
    current.usedAt = now();
    current.reserved = false;
    current.reservationId = "";
    current.reservedAt = 0;
    current.recoveryIdentityVerifier = "";
    recovery.stage = "passwordChanged";
    recovery.identityVerified = false;
    return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
  } catch {
    const current = resetTokens.get(recovery.tokenHash);
    if (current === record && current.reserved && current.reservationId === reservationId && !current.used) {
      current.reserved = false;
      current.reservationId = "";
      current.reservedAt = 0;
    }
    return error("Your password could not be saved. Your recovery instruction is still available; please try again.");
  }
}
async function login(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter your account details and password."); }
  const id = identifier(input.identifier), key = await digest(id || "invalid-account");
  if (loginFailures.get(key)?.lockUntil > now()) return locked();
  const account = id ? accounts.get(key) : undefined;
  const valid = Boolean(account && typeof input.password === "string" && await Bun.password.verify(input.password, account.passwordHash));
  if (!valid) {
    const failures = loginFailures.get(key) || { failures: 0, lockUntil: 0 };
    if (++failures.failures >= 5) failures.lockUntil = now() + LOCK_MS;
    loginFailures.set(key, failures);
    return error(failures.failures >= 5 ? "For safety, please pause for five minutes before another sign-in attempt." : "Those sign-in details did not match. You can try again or use password recovery.", 401);
  }
  loginFailures.delete(key);
  check.session.authenticatedAccount = null; check.session.privacyAccepted = false;
  check.session.mfa = {
    accountKey: key, demoCode: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000), possessionCode: mockCode(8),
    codeConfirmed: false, independentPossession: false, completed: false, expiresAt: now() + MFA_MS,
    failures: 0, lockUntil: 0, possessionFailures: 0, possessionLockUntil: 0,
  };
  return json({ ok: true, message: "Password confirmed. Enter the six-digit demonstration code, then enter the separate possession value.", testMfaCode: check.session.mfa.demoCode, testPossessionValue: check.session.mfa.possessionCode });
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
  const mfa = check.session.mfa, value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  if (!mfa || mfa.expiresAt <= now()) return error("That sign-in check has expired. Sign in again and complete MFA when ready.", 401);
  if (!mfa.codeConfirmed) return error("First enter the six-digit demonstration code.");
  if (mfa.possessionLockUntil > now()) return locked();
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, mfa.possessionCode)) {
    if (++mfa.possessionFailures >= 5) mfa.possessionLockUntil = now() + LOCK_MS;
    return error(mfa.possessionFailures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That separate possession value did not match. Check the simulated delivery message and try again.");
  }
  mfa.possessionCode = ""; mfa.independentPossession = true; mfa.completed = true; check.session.authenticatedAccount = mfa.accountKey;
  return json({ ok: true, message: "Separate possession value confirmed. You are signed in." });
}
function authenticated(session: any) { return Boolean(session?.authenticatedAccount && session.mfa?.completed && session.mfa?.independentPossession && session.mfa.expiresAt > now()); }
function mfaExpired(session: any) { return Boolean(session?.mfa && session.mfa.expiresAt <= now()); }
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
  return {
    ok: true, recoveryStage: session.recovery?.stage || "start", authenticated: authenticated(session), mfaExpired: mfaExpired(session),
    privacyAccepted: session.privacyAccepted, appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed && session.mfa.expiresAt > now()),
    mfaStage: session.mfa?.codeConfirmed ? "possession" : "code", resetAvailable: Boolean(resetRecord(session)),
  };
}

function page(nonce: string, csrf: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hospital account recovery</title>
<style nonce="${nonce}">
body{margin:0;background:#f5f8f9;color:#163043;font:18px/1.5 system-ui,sans-serif}header,main{padding:1rem max(1.2rem,calc((100% - 850px)/2))}header{display:flex;justify-content:space-between;gap:1rem;align-items:center;background:#fff;border-bottom:4px solid #075e8d;font-weight:800}main{padding-top:1.2rem}.card{background:#fff;border:1px solid #b9cbd4;border-radius:12px;padding:1.2rem;margin:1rem 0}h1{font-size:2rem;line-height:1.2}h2{font-size:1.35rem}label{display:block;font-weight:700;margin-top:1rem}input{box-sizing:border-box;display:block;width:100%;max-width:560px;font:inherit;padding:.6rem;border:2px solid #718894;border-radius:7px}button{font:inherit;font-weight:700;background:#075e8d;color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:#075e8d;border:2px solid #075e8d}.feedback{border-left:5px solid #075e8d;background:#eef7fa;padding:.7rem;margin:1rem 0}.error{border-color:#7a4300;background:#fff5e9}.good{border-color:#075d43;background:#ebf8f1}.hide,[hidden]{display:none!important}.progress{margin:1rem 0;padding:0;display:grid;grid-template-columns:repeat(7,1fr);gap:.35rem;list-style:none}.progress li{font-size:.78rem;background:#e4ebee;padding:.45rem;border-radius:6px}.progress .active{background:#075e8d;color:#fff;font-weight:800}.progress .done{background:#d8efe4}.logs{background:#12242e;color:#def2ee;padding:.8rem;border-radius:8px;max-height:180px;overflow:auto;font:14px ui-monospace,monospace}.logs p{margin:.25rem 0}.helpbox{border-left:5px solid #e99b27;background:#fff8e9;padding:.8rem;margin-top:.8rem}a:focus,input:focus,button:focus{outline:3px solid #e99b27;outline-offset:3px}@media(max-width:680px){.progress{grid-template-columns:repeat(2,1fr)}header{align-items:flex-start;flex-direction:column}}
</style></head><body>
<header><span>Hospital secure account portal</span><button id="help" class="secondary" type="button">Need help?</button></header><main>
<h1>Password recovery, one calm step at a time</h1><p id="next">Start by asking for a secure recovery instruction.</p>
<nav aria-label="Recovery progress"><ol class="progress" id="progress"><li data-step="request">1. Request recovery</li><li data-step="instruction">2. Confirm token</li><li data-step="identity">3. Verify identity</li><li data-step="password">4. New password</li><li data-step="login">5. Sign in & safety</li><li data-step="privacy">6. Privacy</li><li data-step="appointment">7. Appointment</li></ol></nav>
<section id="request" class="card"><h2>1. Ask for a recovery instruction</h2><form id="rf"><label>Email address or account reference<input id="id" maxlength="120" autocomplete="username"></label><button>Prepare recovery instruction</button></form><div id="rmsg" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><div id="rdelivery" aria-live="polite"></div><button id="rnext" class="secondary hide" type="button">Continue</button></section>
<section id="instruction" class="card" hidden><h2>2. Confirm recovery token</h2><p>Paste or type the testing mock reset token here.</p><form id="tf"><label>Testing mock reset token<input id="token" maxlength="200" autocomplete="one-time-code"></label><button>Confirm testing mock token</button></form><div id="tmsg" class="feedback" aria-live="polite"></div><button id="newrecovery" class="secondary hide" type="button">Request new recovery instructions</button><button id="tnext" class="secondary hide" type="button">Continue to identity check</button></section>
<section id="identity" class="card" hidden><h2>3. Verify recovery identity</h2><form id="if"><label>Testing mock recovery identity value<input id="identityValue" maxlength="20"></label><button>Confirm recovery identity value</button></form><div id="imsg" class="feedback" aria-live="polite"></div><button id="identitynew" class="secondary hide" type="button">Request new recovery instructions</button><button id="inext" class="secondary hide" type="button">Continue to new password</button></section>
<section id="password" class="card" hidden><h2>4. Choose a new password</h2><p>Use 12 or more characters, with uppercase, lowercase, number, and symbol.</p><form id="pf"><label>New password<input id="pw" type="password" autocomplete="new-password"></label><label>Confirm new password<input id="cpw" type="password" autocomplete="new-password"></label><button>Save new password</button></form><div id="pmsg" class="feedback" aria-live="polite"></div><button id="pnext" class="secondary hide" type="button">Continue to sign in</button></section>
<section id="login" class="card" hidden><h2>5. Sign in and complete safety checks</h2><form id="lf"><label>Account reference<input id="lid" autocomplete="username"></label><label>Password<input id="lpw" type="password" autocomplete="current-password"></label><button>Sign in securely</button></form><div id="lmsg" class="feedback" aria-live="polite"></div><button id="lnext" class="secondary hide" type="button">Continue to safety code</button></section>
<section id="mfa" class="card" hidden><h2>5. Sign in and complete safety checks</h2><form id="mf"><label>Six-digit demonstration code<input id="code" maxlength="6" inputmode="numeric"></label><button>Confirm code</button></form><form id="vf" class="hide"><label>Separate possession value<input id="pos" maxlength="20"></label><button>Confirm possession value</button></form><div id="mmsg" class="feedback" aria-live="polite"></div><button id="restartlogin" class="secondary hide" type="button">Restart sign-in for a new safety code</button><button id="mnext" class="secondary hide" type="button">Continue to privacy conditions</button></section>
<section id="privacy" class="card" hidden><h2>6. Updated privacy conditions</h2><p>Your information is used only for healthcare and appointment coordination.</p><button id="accept" type="button">I accept the updated privacy conditions</button><div id="qmsg" class="feedback" aria-live="polite"></div><button id="qnext" class="secondary hide" type="button">Continue to appointment request</button></section>
<section id="appointment" class="card" hidden><h2>7. Confirm medication review request</h2><button id="book" type="button">Confirm appointment request</button><div id="amsg" class="feedback" aria-live="polite"></div></section>
<section id="helpbox" class="card helpbox" hidden aria-live="polite"><h2>Hospital account support</h2><p>Pause whenever you need to. Contact Hospital Account Support through the hospital switchboard or your usual hospital contact for help returning to this task.</p><p><strong>Safety reminder:</strong> hospital staff will never ask for your password or recovery code by email, text message, or phone. Do not share them.</p><button id="closehelp" class="secondary" type="button">Close help</button></section>
<section class="card"><h2>Logs</h2><div id="logs" class="logs" aria-live="polite"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},$=id=>document.getElementById(id),all=["request","instruction","identity","password","login","mfa","privacy","appointment"],order=["request","instruction","identity","password","login","privacy","appointment"];
const get=k=>sessionStorage.getItem(k)||"",put=(k,v)=>sessionStorage.setItem(k,v),drop=k=>sessionStorage.removeItem(k);
let saved=get("hospital-id"),token=get("hospital-recovery-token"),identity=get("hospital-recovery-identity"),mfaCodeValue=get("hospital-mfa-code"),possession=get("hospital-mfa-possession");
function clearRecovery(){["hospital-recovery-token","hospital-recovery-identity"].forEach(drop);token="";identity=""}
function clearMfa(){["hospital-mfa-code","hospital-mfa-possession"].forEach(drop);mfaCodeValue="";possession=""}
function log(text){console.log(text);const p=document.createElement("p");p.textContent=text;$("logs").append(p)}
function msg(id,text,good){const e=$(id);e.textContent=typeof text==="string"?text:"Please try again.";e.className="feedback "+(good?"good":"error")}
function show(name){all.forEach(id=>$(id).hidden=id!==name);const step=name==="mfa"?"login":name;document.querySelectorAll("#progress li").forEach(x=>{x.classList.toggle("active",x.dataset.step===step);x.classList.toggle("done",order.indexOf(x.dataset.step)<order.indexOf(step))});const cur=document.querySelector('#progress li[data-step="'+step+'"]');$("next").textContent="Current step: "+(cur?cur.textContent:"")+" You can pause and return whenever you need.";window.scrollTo({top:0,behavior:"smooth"})}
async function api(path,data){try{const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)}),result=await response.json();return result&&typeof result==="object"?result:{ok:false,message:"The secure portal could not complete that step. Please try again."}}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}
function recoveryResume(stage){if(stage==="instruction"){if(token){$("token").value=token;log("[mock delivery restored] TESTING MOCK RESET TOKEN: "+token)}else{$("newrecovery").classList.remove("hide");msg("tmsg","The saved recovery token is unavailable. Request new recovery instructions to continue safely.",false)}}if(stage==="identity"){if(identity){$("identityValue").value=identity;log("[mock delivery restored] TESTING MOCK RECOVERY IDENTITY VALUE: "+identity);msg("imsg","Your simulated recovery identity value has been restored in the field.",true)}else{$("identitynew").classList.remove("hide");msg("imsg","The saved recovery identity value is unavailable. Request new recovery instructions to continue safely.",false)}}}
function mfaResume(stage){$("restartlogin").classList.add("hide");if(stage==="code"){if(mfaCodeValue){$("code").value=mfaCodeValue;log("[mock MFA restored] Demonstration code: "+mfaCodeValue);msg("mmsg","Your simulated safety code has been restored in the field.",true)}else{$("restartlogin").classList.remove("hide");msg("mmsg","The saved safety code is unavailable. Restart sign-in for a new safety code.",false)}}else{$("vf").classList.remove("hide");if(possession){$("pos").value=possession;log("[mock MFA restored] DISTINCT TESTING MOCK POSSESSION VALUE: "+possession);msg("mmsg","Your simulated possession value has been restored in the field.",true)}else{$("restartlogin").classList.remove("hide");msg("mmsg","The saved possession value is unavailable. Restart sign-in for a new safety code.",false)}}}
function renderLink(path){const target=$("rdelivery");target.replaceChildren();if(typeof path!=="string"||!path.startsWith("/")||path.startsWith("//"))return;try{const u=new URL(path,location.origin);if(u.origin!==location.origin||u.pathname!=="/"||!u.searchParams.has("recovery-test")||u.hash)return;const a=document.createElement("a");a.href=u.pathname+u.search;a.textContent="Open simulated recovery instruction";target.append(a)}catch{}}
$("help").onclick=()=>{$("helpbox").hidden=false;$("helpbox").scrollIntoView({behavior:"smooth"})};$("closehelp").onclick=()=>{$("helpbox").hidden=true};$("id").value=saved;
$("newrecovery").onclick=$("identitynew").onclick=()=>show("request");$("restartlogin").onclick=()=>{clearMfa();$("lid").value=saved;show("login")};
$("rf").onsubmit=async e=>{e.preventDefault();clearRecovery();saved=$("id").value.trim();put("hospital-id",saved);const r=await api("/api/recovery/request",{identifier:saved});msg("rmsg",r.message,r.ok);renderLink(r.ok?r.deliveryPath:"");if(r.ok&&r.testValue){token=r.testValue;identity=r.testIdentityValue;put("hospital-recovery-token",token);put("hospital-recovery-identity",identity);log("[mock delivery] TESTING MOCK RESET TOKEN: "+token);log("[mock delivery] TESTING MOCK RECOVERY IDENTITY VALUE: "+identity)}if(r.ok)$("rnext").classList.remove("hide")};
$("rnext").onclick=()=>{show("instruction");recoveryResume("instruction")};
$("tf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/instruction",{value:$("token").value.trim()});msg("tmsg",r.message,r.ok);if(r.ok){drop("hospital-recovery-token");token="";$("tnext").classList.remove("hide")}};$("tnext").onclick=()=>{show("identity");recoveryResume("identity")};
$("if").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/identity",{value:$("identityValue").value.trim()});msg("imsg",r.message,r.ok);if(r.ok){drop("hospital-recovery-identity");identity="";$("inext").classList.remove("hide")}};$("inext").onclick=()=>show("password");
$("pf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/password",{password:$("pw").value,confirmPassword:$("cpw").value});msg("pmsg",r.message,r.ok);if(r.ok){clearRecovery();log("[mock verification] Password replacement completed.");$("pnext").classList.remove("hide")}};$("pnext").onclick=()=>{$("lid").value=saved;show("login")};
$("lf").onsubmit=async e=>{e.preventDefault();clearMfa();const r=await api("/api/login",{identifier:$("lid").value,password:$("lpw").value});msg("lmsg",r.message,r.ok);if(r.ok){mfaCodeValue=r.testMfaCode;possession=r.testPossessionValue;put("hospital-mfa-code",mfaCodeValue);put("hospital-mfa-possession",possession);log("[mock MFA] Demonstration code: "+mfaCodeValue);log("[mock MFA] DISTINCT TESTING MOCK POSSESSION VALUE: "+possession);$("lnext").classList.remove("hide")}};$("lnext").onclick=()=>{show("mfa");mfaResume("code")};
$("mf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa/code",{code:$("code").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok){drop("hospital-mfa-code");mfaCodeValue="";$("vf").classList.remove("hide")}};
$("vf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa/possession",{value:$("pos").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok){clearMfa();$("mnext").classList.remove("hide")}};$("mnext").onclick=()=>show("privacy");
$("accept").onclick=async()=>{const r=await api("/api/privacy/accept",{});msg("qmsg",r.message,r.ok);if(r.ok)$("qnext").classList.remove("hide")};$("qnext").onclick=()=>show("appointment");$("book").onclick=async()=>{const r=await api("/api/appointment",{});msg("amsg",r.message,r.ok);if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};
(async()=>{const url=new URL(location.href),incoming=url.searchParams.get("recovery-test");if(incoming){token=incoming;put("hospital-recovery-token",token);history.replaceState(null,"",location.pathname);const r=await api("/api/recovery/instruction",{value:token});if(r.ok){drop("hospital-recovery-token");token="";log("[mock delivery] Simulated recovery instruction securely confirmed. Enter the recovery identity value.");show("identity");recoveryResume("identity");msg("imsg",r.message,true)}else{show("instruction");recoveryResume("instruction");msg("tmsg",r.message,false);log("[mock delivery] Recovery link could not be confirmed. Manual token entry remains available.")}return}try{const s=await(await fetch("/api/state",{credentials:"same-origin"})).json();if(s.mfaExpired){clearMfa();show("login");$("lid").value=saved;msg("lmsg","Your MFA safety check expired. Please sign in and complete MFA again.",false)}else if(s.appointmentBooked)show("appointment");else if(s.authenticated&&s.privacyAccepted)show("appointment");else if(s.authenticated)show("privacy");else if(s.needsMfa){show("mfa");mfaResume(s.mfaStage)}else if(s.recoveryStage==="passwordChanged")show("login");else if(s.recoveryStage==="identityVerified")show("password");else if(s.recoveryStage==="identity"){show("identity");recoveryResume("identity")}else if(s.recoveryStage==="instructionSent"){show("instruction");recoveryResume("instruction")}else show("request")}catch{show("request")}})();
})();</script></body></html>`;
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
      if (request.headers.get("x-forwarded-proto") === "http") return respond("Secure HTTPS connection required.", 426, "text/plain; charset=utf-8");
      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request); const fresh = !session;
        if (!session) session = newSession();
        /* Recovery-link GET is deliberately non-mutating. */
        const recoveryTest = url.searchParams.get("recovery-test");
        if (recoveryTest !== null) /^[A-Za-z0-9_-]{20,200}$/.test(recoveryTest);
        const nonce = randomToken(18);
        return respond(page(nonce, session.csrf), 200, "text/html; charset=utf-8", nonce, fresh ? { "Set-Cookie": sessionCookie(session.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        return session ? json(state(session)) : error("Please open the secure portal first.", 401);
      }
      const routes: Record<string, (request: Request) => Promise<Response>> = {
        "/api/recovery/request": recoveryRequest, "/api/recovery/instruction": confirmInstruction, "/api/recovery/identity": recoveryIdentity,
        "/api/recovery/password": replacePassword, "/api/login": login, "/api/mfa/code": mfaCode, "/api/mfa/possession": mfaPossession,
        "/api/privacy/accept": privacy, "/api/appointment": appointment,
      };
      return request.method === "POST" && routes[url.pathname] ? await routes[url.pathname](request) : respond("Not found.", 404, "text/plain; charset=utf-8");
    } catch { return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8"); }
  },
});
console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
