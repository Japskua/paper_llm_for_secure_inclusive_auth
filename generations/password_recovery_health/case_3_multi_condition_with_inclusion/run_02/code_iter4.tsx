
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: deterministic in-memory mocks, expiry, CSRF, throttling. */
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

function now() { return Date.now(); }

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

async function digest(value: string) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(raw).toString("hex");
}

function newSession() {
  const id = randomToken(32);
  const session = {
    id,
    csrf: randomToken(32),
    createdAt: now(),
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

function cookieValue(request: Request, key: string) {
  const source = request.headers.get("cookie") || "";
  const found = source.split(";").map((part) => part.trim()).find((part) => part.startsWith(key + "="));
  return found ? decodeURIComponent(found.slice(key.length + 1)) : "";
}

/* Requirement 3: expired sessions are rejected and deleted during every lookup. */
function getSession(request: Request) {
  const id = cookieValue(request, COOKIE);
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  if (session.expiresAt <= now()) {
    sessions.delete(id);
    return undefined;
  }
  return session;
}

function cleanupExpired() {
  const time = now();
  for (const [id, session] of sessions) if (session.expiresAt <= time) sessions.delete(id);
  for (const [key, times] of recoveryIssues) {
    const kept = times.filter((value) => value > time - RECOVERY_WINDOW_MS);
    if (kept.length) recoveryIssues.set(key, kept);
    else recoveryIssues.delete(key);
  }
  for (const [key, failure] of loginFailures) {
    if (failure.lockUntil && failure.lockUntil <= time && failure.failures >= 5) loginFailures.delete(key);
  }
}
setInterval(cleanupExpired, 60_000);

function securityHeaders(nonce = "") {
  const csp = nonce
    ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`
    : "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": csp,
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
function json(body: any, status = 200, extra: Record<string, string> = {}) {
  return respond(JSON.stringify(body), status, "application/json; charset=utf-8", "", extra);
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
  if (!Number.isFinite(length) || length > 8192) throw new Error("too large");
  const body = await request.json();
  return body && typeof body === "object" && !Array.isArray(body) ? body : {};
}

/* Requirement 1: session-bound CSRF and same-origin checks for every state change. */
function validateSensitiveRequest(request: Request) {
  const session = getSession(request);
  if (!session) return { error: apiError("Please return to the secure portal and try again.", 401) };
  const origin = request.headers.get("origin");
  if (origin !== new URL(request.url).origin) {
    return { error: apiError("This request could not be confirmed safely. Please try again in the portal.", 403) };
  }
  if (request.headers.get("x-csrf-token") !== session.csrf) {
    return { error: apiError("Your secure form check did not match. Refresh the page and try again.", 403) };
  }
  return { session };
}

function validIdentifier(value: unknown) {
  if (typeof value !== "string") return "";
  const identifier = value.trim().toLowerCase();
  if (identifier.length < 3 || identifier.length > 120) return "";
  return /^[a-z0-9@._+\- ]+$/.test(identifier) ? identifier : "";
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

/*
 Requirement task: recovery throttling is session-bound. It deliberately does not
 read X-Forwarded-For or X-Real-IP, which are attacker-controlled unless a
 separately configured trusted proxy explicitly normalizes them.
*/
function recoveryThrottleKey(session: any, accountKey: string) {
  return `${session.id}:${accountKey}`;
}

function recoveryAllowed(key: string) {
  const cutoff = now() - RECOVERY_WINDOW_MS;
  const recent = (recoveryIssues.get(key) || []).filter((time) => time > cutoff);
  if (recent.length >= RECOVERY_MAX_ISSUES) {
    recoveryIssues.set(key, recent);
    return false;
  }
  recent.push(now());
  recoveryIssues.set(key, recent);
  return true;
}

function lockMessage() {
  return apiError("For safety, please pause for five minutes before trying again.", 429);
}

/*
 Requirement task: stale reset authorization is never restored as a verified
 recovery. This only keeps generic orientation; it exposes no account status.
*/
function downgradeExpiredRecovery(session: any) {
  const reset = session.reset;
  if (reset && !reset.used && reset.expiresAt <= now()) {
    session.reset = null;
    if (session.recovery?.stage === "sent" || session.recovery?.stage === "verified") {
      session.recovery = { stage: "expired" };
    }
  }
}

function publicState(session: any) {
  downgradeExpiredRecovery(session);
  return {
    ok: true,
    csrf: session.csrf,
    recoveryStage: session.recovery?.stage || "start",
    authenticated: Boolean(session.authenticatedAccount),
    privacyAccepted: session.privacyAccepted,
    appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed && session.mfa.expiresAt > now()),
  };
}

/*
 Requirement task: all syntactically valid recovery requests receive the same
 response. Every session receives a reset-shaped record: for unrecognized
 identifiers it is a session-local decoy that can pass the demonstration code
 step but can never change an account, authenticate, expose data, or create one.
*/
function genericRecoveryResponse(token: string) {
  return json({
    ok: true,
    message: "If the account can receive recovery instructions, a secure instruction has been prepared. Continue when you are ready.",
    deliveryPath: `/?reset=${encodeURIComponent(token)}`,
    testToken: token,
  });
}

/* Requirement 4: only pre-provisioned accounts are eligible; unknown identifiers never create accounts. */
async function resetRequest(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Please enter your account details in the form."); }

  const identifier = validIdentifier(body.identifier);
  if (!identifier) return apiError("Enter an email address or account reference using letters, numbers, and common punctuation.");

  const accountKey = await digest(identifier);
  const account = accounts.get(accountKey);
  const demonstrationToken = randomToken(32);
  const allowed = recoveryAllowed(recoveryThrottleKey(checked.session, accountKey));

  /*
   A throttled request deliberately gets the same generic delivery response and
   a decoy authorization. Nothing browser-visible reveals why it is decoy.
  */
  checked.session.recovery = { stage: "sent" };
  checked.session.reset = {
    token: demonstrationToken,
    accountKey: account && allowed ? accountKey : null,
    decoy: !account || !allowed,
    expiresAt: now() + 15 * 60 * 1000,
    used: false,
    verified: false,
    failures: 0,
    lockUntil: 0,
  };
  return genericRecoveryResponse(demonstrationToken);
}

function constantTimeTokenMatches(supplied: string, expected: string) {
  if (supplied.length !== expected.length || supplied.length === 0) return false;
  try {
    return timingSafeEqual(Buffer.from(supplied, "utf8"), Buffer.from(expected, "utf8"));
  } catch {
    return false;
  }
}

/*
 Requirement task: known and unknown identifiers follow the same verification
 response path. A valid session-local decoy token confirms normally, but has no
 account binding and cannot later authorize password replacement.
*/
async function verifyReset(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter the recovery code."); }

  downgradeExpiredRecovery(checked.session);
  const reset = checked.session.reset;
  const supplied = typeof body.token === "string" ? body.token.trim() : "";
  if (!reset || reset.used || reset.expiresAt <= now()) {
    return apiError("This recovery code is no longer available. You can calmly request a new one.");
  }
  if (reset.lockUntil > now()) return lockMessage();
  if (!constantTimeTokenMatches(supplied, reset.token)) {
    reset.failures++;
    if (reset.failures >= 5) reset.lockUntil = now() + 5 * 60 * 1000;
    return apiError(reset.failures >= 5
      ? "For safety, please pause for five minutes, then request a fresh code if needed."
      : "That code did not match. Check it and try again.");
  }
  reset.verified = true;
  checked.session.recovery = { stage: "verified" };
  return json({ ok: true, message: "Code confirmed. Your next step is to choose a new password." });
}

async function replacePassword(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Please complete both password fields."); }

  downgradeExpiredRecovery(checked.session);
  const reset = checked.session.reset;
  if (!reset || reset.used || !reset.verified || reset.expiresAt <= now()) {
    return apiError("Please verify a current recovery code before changing your password.");
  }
  const problem = passwordProblem(body.password);
  if (problem) return apiError(problem);
  if (body.password !== body.confirmPassword) return apiError("The two passwords do not match yet.");

  /*
   Decoy completion intentionally mirrors normal recovery completion. It consumes
   its single-use authorization without writing any account record.
  */
  if (!reset.decoy && typeof reset.accountKey === "string") {
    const account = accounts.get(reset.accountKey);
    if (account) account.passwordHash = await Bun.password.hash(body.password, { algorithm: "argon2id" });
  }
  reset.token = "";
  reset.used = true;
  checked.session.recovery = { stage: "passwordChanged" };
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}

async function login(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter your account details and password."); }

  const identifier = validIdentifier(body.identifier);
  const accountKey = await digest(identifier || "invalid-account");
  const failure = loginFailures.get(accountKey);
  if (failure && failure.lockUntil > now()) return lockMessage();

  const account = identifier ? accounts.get(accountKey) : undefined;
  const valid = Boolean(account && account.passwordHash && typeof body.password === "string" &&
    await Bun.password.verify(body.password, account.passwordHash));

  if (!valid) {
    const current = loginFailures.get(accountKey) || { failures: 0, lockUntil: 0 };
    current.failures++;
    if (current.failures >= 5) current.lockUntil = now() + 5 * 60 * 1000;
    loginFailures.set(accountKey, current);
    return apiError(current.failures >= 5
      ? "For safety, please pause for five minutes before another sign-in attempt."
      : "Those sign-in details did not match. You can try again or use password recovery.", 401);
  }

  loginFailures.delete(accountKey);
  checked.session.mfa = {
    code: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000),
    accountKey,
    expiresAt: now() + 10 * 60 * 1000,
    failures: 0,
    lockUntil: 0,
    completed: false,
  };
  return json({ ok: true, message: "Password confirmed. Enter the six-digit safety code to finish signing in.", testMfaCode: checked.session.mfa.code });
}

async function verifyMfa(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter the six-digit safety code."); }

  const mfa = checked.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return apiError("That safety code has expired. Sign in again when ready.");
  if (mfa.lockUntil > now()) return lockMessage();
  if (typeof body.code !== "string" || !constantTimeTokenMatches(body.code, mfa.code)) {
    mfa.failures++;
    if (mfa.failures >= 5) mfa.lockUntil = now() + 5 * 60 * 1000;
    return apiError(mfa.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again.");
  }
  mfa.completed = true;
  checked.session.authenticatedAccount = mfa.accountKey;
  return json({ ok: true, message: "You are signed in. The next step is to read and accept the updated privacy conditions." });
}

function authenticated(session: any) {
  return Boolean(session?.authenticatedAccount && session.mfa?.completed);
}

async function acceptPrivacy(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  if (!authenticated(checked.session)) return apiError("Please sign in before changing privacy conditions.", 401);
  checked.session.privacyAccepted = true;
  return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}

async function bookAppointment(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  if (!authenticated(checked.session) || !checked.session.privacyAccepted) {
    return apiError("Please accept the privacy conditions before confirming an appointment.", 403);
  }
  checked.session.appointmentBooked = true;
  return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}

/* Requirements accessibility and inclusivity: a quiet, focused SPA with explicit Continue controls. */
function page(nonce: string, csrf: string) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--ink:#163043;--blue:#075e8d;--pale:#eef7fa;--line:#b9cbd4;--good:#075d43;--warn:#7a4300}*{box-sizing:border-box}body{margin:0;background:#f5f8f9;color:var(--ink);font:18px/1.52 system-ui,sans-serif}header{background:#fff;border-bottom:4px solid var(--blue);padding:1rem max(1.2rem,calc((100% - 900px)/2))}.brand{font-weight:800;font-size:1.2rem}main{max-width:900px;margin:auto;padding:1.5rem 1.2rem 4rem}h1{font-size:2rem;line-height:1.2}h2{font-size:1.35rem;line-height:1.25}.progress,.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.2rem;margin:1rem 0}.progress ol{display:flex;gap:.45rem;list-style:none;padding:0;margin:.7rem 0 0;flex-wrap:wrap}.progress li{background:#e6edf0;border-radius:99px;padding:.22rem .65rem;font-size:.87rem}.progress li.active{background:var(--blue);color:#fff}.panel[hidden],.hide{display:none!important}label{display:block;font-weight:700;margin-top:1rem}input{display:block;width:100%;max-width:560px;font:inherit;padding:.62rem;border:2px solid #718894;border-radius:7px}input:focus,button:focus,a:focus{outline:3px solid #e99b27;outline-offset:3px}button{font:inherit;font-weight:700;background:var(--blue);color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.feedback{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .9rem;margin:1rem 0;min-height:1.6rem}.feedback.error{border-color:var(--warn);background:#fff5e9}.feedback.good{border-color:var(--good);background:#ebf8f1}.help{background:#fff8df;border:1px solid #d8bc64;border-radius:9px;padding:1rem}.logs{background:#12242e;color:#def2ee;border-radius:8px;padding:.8rem;max-height:180px;overflow:auto;font:14px/1.4 ui-monospace,monospace}.logs p{margin:.25rem 0}.small{font-size:.92rem}@media(max-width:550px){body{font-size:17px}.progress ol{display:block}.progress li{display:inline-block;margin:.15rem}}
</style></head><body>
<header><div class="brand">Hospital secure account portal</div></header><main>
<h1>Password recovery, one calm step at a time</h1><p id="nextInstruction">Start by asking for a secure recovery instruction.</p>
<nav class="progress" aria-label="Recovery progress"><strong>Your progress</strong><ol><li id="p1">1. Recovery</li><li id="p2">2. Code</li><li id="p3">3. New password</li><li id="p4">4. Sign in</li><li id="p5">5. Privacy & appointment</li></ol></nav>
<section id="requestPanel" class="panel card"><h2>1. Ask for a recovery instruction</h2><p>Enter your email address or account reference. We will not say whether an account is registered.</p><form id="requestForm" novalidate><label for="identifier">Email address or account reference</label><input id="identifier" autocomplete="username" maxlength="120" required><button>Prepare recovery instruction</button></form><div id="requestFeedback" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><p><a id="deliveryLink" class="hide" href="#verify">Open simulated secure recovery instruction</a></p><button id="requestContinue" class="secondary hide" type="button">Continue to code</button></section>
<section id="verifyPanel" class="panel card" hidden><h2>2. Confirm your recovery code</h2><p>Open the secure instruction above, or paste or type its code here. There is no rush.</p><form id="verifyForm" novalidate><label for="resetCode">Recovery code</label><input id="resetCode" autocomplete="one-time-code" maxlength="80" required><button>Confirm code</button></form><div id="verifyFeedback" class="feedback" aria-live="polite">Check the code, then select Confirm code.</div><button id="verifyContinue" class="secondary hide" type="button">Continue to new password</button><button id="backRequest" class="secondary" type="button">Request a new code</button></section>
<section id="passwordPanel" class="panel card" hidden><h2>3. Choose a new password</h2><p>Use 12 or more characters, with an uppercase letter, lowercase letter, number, and symbol.</p><form id="passwordForm" novalidate><label for="newPassword">New password</label><input id="newPassword" type="password" autocomplete="new-password" maxlength="128" required><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required><button>Save new password</button></form><div id="passwordFeedback" class="feedback" aria-live="polite">After saving, you will sign in with your new password.</div><button id="passwordContinue" class="secondary hide" type="button">Continue to sign in</button></section>
<section id="loginPanel" class="panel card" hidden><h2>4. Sign in</h2><p>Use the same account reference and your new password. We will then ask for one safety code.</p><form id="loginForm" novalidate><label for="loginIdentifier">Email address or account reference</label><input id="loginIdentifier" autocomplete="username" maxlength="120" required><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" maxlength="128" required><button>Sign in securely</button></form><div id="loginFeedback" class="feedback" aria-live="polite">You may use password recovery if you need it.</div><button id="loginContinue" class="secondary hide" type="button">Continue to safety code</button></section>
<section id="mfaPanel" class="panel card" hidden><h2>Extra safety check</h2><p>Enter the six-digit safety code from your simulated secure message.</p><form id="mfaForm" novalidate><label for="mfaCode">Six-digit safety code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button>Finish sign in</button></form><div id="mfaFeedback" class="feedback" aria-live="polite">This code is only for this sign-in session.</div><button id="mfaContinue" class="secondary hide" type="button">Continue to privacy conditions</button></section>
<section id="privacyPanel" class="panel card" hidden><h2>5. Updated privacy conditions</h2><p>To allow hospital authorities to arrange the medication dosage review, please accept the updated privacy conditions.</p><ul><li>Your information is used only for healthcare and appointment coordination.</li><li>You can ask hospital staff for help with these conditions.</li></ul><button id="privacyButton" type="button">I accept the updated privacy conditions</button><div id="privacyFeedback" class="feedback" aria-live="polite">Read this at your own pace.</div><button id="privacyContinue" class="secondary hide" type="button">Continue to appointment request</button></section>
<section id="appointmentPanel" class="panel card" hidden><h2>Confirm medication review request</h2><p>Your privacy conditions are accepted. Confirm when you are ready.</p><button id="appointmentButton" type="button">Confirm appointment request</button><div id="appointmentFeedback" class="feedback" aria-live="polite">No appointment is requested until you select the button.</div></section>
<aside class="help"><h2>Need help or a reminder?</h2><p>You can pause and return without a countdown. Contact your usual hospital support channel for help. Hospital staff will never ask you to send a password or recovery code by email or phone. Check that this is the secure hospital portal before entering details.</p></aside>
<section class="card"><h2>Logs</h2><p class="small">Simulated delivery and verification messages are shown here for this demonstration.</p><div id="logs" class="logs" aria-live="polite"></div></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";const csrf=${JSON.stringify(csrf)},$=id=>document.getElementById(id),ids=["requestPanel","verifyPanel","passwordPanel","loginPanel","mfaPanel","privacyPanel","appointmentPanel"];let token="",identifier=sessionStorage.getItem("hospital-recovery-identifier")||"";
function log(m){console.log(m);const p=document.createElement("p");p.textContent=m;$("logs").append(p);$("logs").scrollTop=$("logs").scrollHeight}
function feedback(id,text,kind){const e=$(id);e.textContent=text;e.className="feedback"+(kind?" "+kind:"")}
function choose(id,n,focus){ids.forEach(x=>$(x).hidden=x!==id);for(let i=1;i<6;i++)$("p"+i).classList.toggle("active",i===n);$("nextInstruction").textContent=["Start by asking for a secure recovery instruction.","Your next step is to confirm your recovery code.","Your next step is to choose a strong new password.","Your next step is to sign in and complete the safety check.","You are almost done: accept privacy conditions, then confirm the appointment request."][n-1];window.scrollTo({top:0,behavior:"smooth"});const e=$(focus||id);setTimeout(()=>e.focus&&e.focus(),0)}
function reveal(id){$(id).classList.remove("hide");$(id).focus()}
function safeId(v){return /^[a-z0-9@._+\\- ]{3,120}$/i.test(v.trim())}function safePass(v){return v.length>=12&&v.length<=128&&/[a-z]/.test(v)&&/[A-Z]/.test(v)&&/[0-9]/.test(v)&&/[^A-Za-z0-9]/.test(v)}
async function api(path,data){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});return await r.json()}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}
function openVerify(){choose("verifyPanel",2,"resetCode");if(token)$("resetCode").value=token}
$("identifier").value=identifier;$("deliveryLink").onclick=()=>openVerify();window.onhashchange=()=>{if(location.hash==="#verify")openVerify()};
$("requestForm").onsubmit=async e=>{e.preventDefault();const v=$("identifier").value.trim();if(!safeId(v))return feedback("requestFeedback","Enter an email address or account reference using letters, numbers, and common punctuation.","error");identifier=v;sessionStorage.setItem("hospital-recovery-identifier",v);const r=await api("/api/recovery/request",{identifier:v});feedback("requestFeedback",r.message,r.ok?"good":"error");if(r.ok){token=typeof r.testToken==="string"?r.testToken:"";$("deliveryLink").href=typeof r.deliveryPath==="string"?r.deliveryPath:"#verify";$("deliveryLink").classList.remove("hide");if(token)log("[mock delivery] Recovery token for testing: "+token);reveal("requestContinue")}};
$("requestContinue").onclick=openVerify;$("backRequest").onclick=()=>choose("requestPanel",1,"identifier");
$("verifyForm").onsubmit=async e=>{e.preventDefault();const v=$("resetCode").value.trim();if(!/^[A-Za-z0-9_-]{20,}$/.test(v))return feedback("verifyFeedback","Enter the recovery code from the secure instruction.","error");const r=await api("/api/recovery/verify",{token:v});feedback("verifyFeedback",r.message,r.ok?"good":"error");if(r.ok)reveal("verifyContinue")};$("verifyContinue").onclick=()=>choose("passwordPanel",3,"newPassword");
$("passwordForm").onsubmit=async e=>{e.preventDefault();const p=$("newPassword").value,c=$("confirmPassword").value;if(!safePass(p))return feedback("passwordFeedback","Use 12+ characters with uppercase, lowercase, number, and symbol.","error");if(p!==c)return feedback("passwordFeedback","The two passwords do not match yet.","error");const r=await api("/api/recovery/password",{password:p,confirmPassword:c});feedback("passwordFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock verification] Password replacement completed; recovery token invalidated.");reveal("passwordContinue")}};$("passwordContinue").onclick=()=>{$("loginIdentifier").value=identifier;choose("loginPanel",4,"loginPassword")};
$("loginForm").onsubmit=async e=>{e.preventDefault();const v=$("loginIdentifier").value.trim(),p=$("loginPassword").value;if(!safeId(v)||!p)return feedback("loginFeedback","Enter your account reference and password.","error");const r=await api("/api/login",{identifier:v,password:p});feedback("loginFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock MFA] Safety code for testing: "+r.testMfaCode);reveal("loginContinue")}};$("loginContinue").onclick=()=>choose("mfaPanel",4,"mfaCode");
$("mfaForm").onsubmit=async e=>{e.preventDefault();const c=$("mfaCode").value.trim();if(!/^\\d{6}$/.test(c))return feedback("mfaFeedback","Enter all six digits of the safety code.","error");const r=await api("/api/mfa",{code:c});feedback("mfaFeedback",r.message,r.ok?"good":"error");if(r.ok)reveal("mfaContinue")};$("mfaContinue").onclick=()=>choose("privacyPanel",5,"privacyButton");
$("privacyButton").onclick=async()=>{const r=await api("/api/privacy/accept",{});feedback("privacyFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock privacy] Updated privacy conditions accepted.");reveal("privacyContinue")}};$("privacyContinue").onclick=()=>choose("appointmentPanel",5,"appointmentButton");
$("appointmentButton").onclick=async()=>{const r=await api("/api/appointment",{});feedback("appointmentFeedback",r.message,r.ok?"good":"error");if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};
(async()=>{const incoming=new URL(location.href).searchParams.get("reset");if(incoming&&/^[A-Za-z0-9_-]{20,}$/.test(incoming)){token=incoming;history.replaceState({},"","/#verify");log("[mock delivery] Secure recovery instruction opened.");openVerify();return}try{const s=await(await fetch("/api/state",{credentials:"same-origin"})).json();if(s.appointmentBooked){choose("appointmentPanel",5,"appointmentButton");feedback("appointmentFeedback","Your medication review appointment request is confirmed.","good")}else if(s.authenticated&&s.privacyAccepted)choose("appointmentPanel",5,"appointmentButton");else if(s.authenticated)choose("privacyPanel",5,"privacyButton");else if(s.needsMfa)choose("mfaPanel",4,"mfaCode");else if(s.recoveryStage==="passwordChanged"){$("loginIdentifier").value=identifier;choose("loginPanel",4,"loginPassword")}else if(s.recoveryStage==="verified")choose("passwordPanel",3,"newPassword");else if(s.recoveryStage==="sent")choose("verifyPanel",2,"resetCode");else if(s.recoveryStage==="expired"){choose("requestPanel",1,"identifier");feedback("requestFeedback","Your earlier recovery code has expired. Your place in the process is saved, and a fresh code is needed. Enter your account reference when you are ready.","error");log("[mock recovery] Earlier code expired; a fresh recovery code is needed.")}else choose("requestPanel",1,"identifier")}catch{choose("requestPanel",1,"identifier")}})()})();
</script></body></html>`;
}

/* Pre-provisioned mock accounts. No recovery or login path provisions accounts. */
async function provisionAccounts() {
  for (const identifier of ["helena@example.com", "helena.patient@hospital.test", "helena patient"]) {
    const key = await digest(identifier);
    accounts.set(key, {
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
        const isNew = !session;
        if (!session) session = newSession();
        const nonce = randomToken(18);
        return respond(page(nonce, session.csrf), 200, "text/html; charset=utf-8", nonce, isNew ? { "Set-Cookie": sessionCookie(session.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        return session ? json(publicState(session)) : apiError("Please open the secure portal first.", 401);
      }
      if (request.method === "POST" && url.pathname === "/api/recovery/request") return await resetRequest(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/verify") return await verifyReset(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/password") return await replacePassword(request);
      if (request.method === "POST" && url.pathname === "/api/login") return await login(request);
      if (request.method === "POST" && url.pathname === "/api/mfa") return await verifyMfa(request);
      if (request.method === "POST" && url.pathname === "/api/privacy/accept") return await acceptPrivacy(request);
      if (request.method === "POST" && url.pathname === "/api/appointment") return await bookAppointment(request);
      return notFound();
    } catch {
      return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8");
    }
  },
});

console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
