
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();

const CERT = Bun.file("certs/cert.pem");
const KEY = Bun.file("certs/key.pem");
const COOKIE = "__Host-hospital_recovery";

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

async function digest(value: string) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(raw).toString("hex");
}

function now() {
  return Date.now();
}

function newSession() {
  const id = randomToken(32);
  const session = {
    id,
    csrf: randomToken(32),
    createdAt: now(),
    recovery: null as any,
    reset: null as any,
    loginFailures: 0,
    loginLockUntil: 0,
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

function getSession(request: Request) {
  const id = cookieValue(request, COOKIE);
  return id ? sessions.get(id) : undefined;
}

function secureHeaders(nonce: string) {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'self'; font-src 'none'; base-uri 'none'; form-action 'self'; " +
      "frame-ancestors 'none'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
}

function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`;
}

function json(body: any, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra,
    },
  });
}

async function requestBody(request: Request) {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 8192) throw new Error("Request too large");
  const value = await request.json();
  return value && typeof value === "object" ? value : {};
}

/* Security requirements 1 and 3: session-bound CSRF and same-origin validation. */
function validateSensitiveRequest(request: Request) {
  const session = getSession(request);
  if (!session) return { error: json({ ok: false, message: "Please return to the secure portal and try again." }, 401) };

  const origin = request.headers.get("origin");
  const expectedOrigin = new URL(request.url).origin;
  if (origin !== expectedOrigin) {
    return { error: json({ ok: false, message: "This request could not be confirmed safely. Please try again in the portal." }, 403) };
  }

  if (request.headers.get("x-csrf-token") !== session.csrf) {
    return { error: json({ ok: false, message: "Your secure form check did not match. Refresh the page and try again." }, 403) };
  }
  return { session };
}

function validIdentifier(value: unknown) {
  if (typeof value !== "string") return "";
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 120) return "";
  if (!/^[a-z0-9@._+\- ]+$/.test(normalized)) return "";
  return normalized;
}

function passwordProblem(password: unknown) {
  if (typeof password !== "string") return "Enter a password.";
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Use no more than 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use an uppercase letter, lowercase letter, number, and symbol.";
  }
  return "";
}

function lockResponse() {
  return json({ ok: false, message: "For safety, please pause for a few minutes before trying again." }, 429);
}

function publicState(session: any) {
  return {
    ok: true,
    csrf: session.csrf,
    recoveryStage: session.recovery?.stage || "start",
    hasReset: Boolean(session.reset && !session.reset.used && session.reset.expiresAt > now()),
    authenticated: Boolean(session.authenticatedAccount),
    privacyAccepted: session.privacyAccepted,
    appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed),
  };
}

/* Requirements 3 and 4: random, single-use, short-lived recovery tokens. */
async function resetRequest(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  const session = checked.session;
  let body: any;
  try { body = await requestBody(request); } catch { return json({ ok: false, message: "Please enter your account details in the form." }, 400); }

  const identifier = validIdentifier(body.identifier);
  if (!identifier) return json({ ok: false, message: "Enter an email address or account reference using letters, numbers, and common punctuation." }, 400);

  const accountKey = await digest(identifier);
  let account = accounts.get(accountKey);
  if (!account) {
    account = { passwordHash: "", createdAt: now() };
    accounts.set(accountKey, account);
  }

  const token = randomToken(32);
  session.recovery = { stage: "sent", accountKey };
  session.reset = {
    token,
    accountKey,
    expiresAt: now() + 15 * 60 * 1000,
    used: false,
    failures: 0,
    lockUntil: 0,
    verified: false,
  };

  console.log("[mock delivery] Secure reset instruction created for this session.");
  return json({
    ok: true,
    message: "If the account can receive recovery instructions, a secure instruction has been prepared. Continue when you are ready.",
    deliveryPath: "/?reset=" + encodeURIComponent(token),
    testToken: token,
  });
}

async function verifyReset(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  const session = checked.session;
  let body: any;
  try { body = await requestBody(request); } catch { return json({ ok: false, message: "Enter the recovery code." }, 400); }

  const reset = session.reset;
  const supplied = typeof body.token === "string" ? body.token.trim() : "";
  if (!reset || reset.used || reset.expiresAt <= now()) {
    return json({ ok: false, message: "This recovery code is no longer available. You can calmly request a new one." }, 400);
  }
  if (reset.lockUntil > now()) return lockResponse();

  if (supplied.length !== reset.token.length || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(reset.token))) {
    reset.failures++;
    if (reset.failures >= 5) reset.lockUntil = now() + 5 * 60 * 1000;
    return json({ ok: false, message: reset.failures >= 5 ? "For safety, please pause for five minutes, then request a fresh code if needed." : "That code did not match. Check it and try again." }, 400);
  }

  reset.verified = true;
  session.recovery.stage = "verified";
  return json({ ok: true, message: "Code confirmed. Your next step is to choose a new password." });
}

async function replacePassword(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  const session = checked.session;
  let body: any;
  try { body = await requestBody(request); } catch { return json({ ok: false, message: "Please complete both password fields." }, 400); }

  const reset = session.reset;
  if (!reset || reset.used || !reset.verified || reset.expiresAt <= now()) {
    return json({ ok: false, message: "Please verify a current recovery code before changing your password." }, 400);
  }
  const problem = passwordProblem(body.password);
  if (problem) return json({ ok: false, message: problem }, 400);
  if (body.password !== body.confirmPassword) return json({ ok: false, message: "The two passwords do not match yet." }, 400);

  const account = accounts.get(reset.accountKey);
  if (!account) return json({ ok: false, message: "Please request a new recovery instruction and try again." }, 400);

  /* Requirement 4: password is only retained as an Argon2id hash. */
  account.passwordHash = await Bun.password.hash(body.password, { algorithm: "argon2id" });
  reset.used = true;
  reset.token = "";
  session.recovery.stage = "passwordChanged";
  console.log("[mock verification] Password replacement completed; recovery token invalidated.");
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}

async function login(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  const session = checked.session;
  let body: any;
  try { body = await requestBody(request); } catch { return json({ ok: false, message: "Enter your account details and password." }, 400); }
  if (session.loginLockUntil > now()) return lockResponse();

  const identifier = validIdentifier(body.identifier);
  const accountKey = identifier ? await digest(identifier) : "";
  const account = accountKey ? accounts.get(accountKey) : undefined;
  const valid = account && account.passwordHash && typeof body.password === "string" &&
    await Bun.password.verify(body.password, account.passwordHash);

  if (!valid) {
    session.loginFailures++;
    if (session.loginFailures >= 5) session.loginLockUntil = now() + 5 * 60 * 1000;
    return json({ ok: false, message: session.loginFailures >= 5 ? "For safety, please pause for five minutes before another sign-in attempt." : "Those sign-in details did not match. You can try again or use password recovery." }, 401);
  }

  session.loginFailures = 0;
  session.mfa = { code: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000), expiresAt: now() + 10 * 60 * 1000, failures: 0, lockUntil: 0, completed: false, accountKey };
  console.log("[mock MFA] A session-bound safety code was generated.");
  return json({ ok: true, message: "Password confirmed. Enter the six-digit safety code to finish signing in.", testMfaCode: session.mfa.code });
}

async function verifyMfa(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  const session = checked.session;
  let body: any;
  try { body = await requestBody(request); } catch { return json({ ok: false, message: "Enter the six-digit safety code." }, 400); }

  const mfa = session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return json({ ok: false, message: "That safety code has expired. Sign in again when ready." }, 400);
  if (mfa.lockUntil > now()) return lockResponse();
  if (typeof body.code !== "string" || body.code !== mfa.code) {
    mfa.failures++;
    if (mfa.failures >= 5) mfa.lockUntil = now() + 5 * 60 * 1000;
    return json({ ok: false, message: mfa.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again." }, 400);
  }

  mfa.completed = true;
  session.authenticatedAccount = mfa.accountKey;
  session.recovery.stage = "signedIn";
  return json({ ok: true, message: "You are signed in. The next step is to read and accept the updated privacy conditions." });
}

function requireAuthenticated(session: any) {
  return session && session.authenticatedAccount && session.mfa?.completed;
}

async function acceptPrivacy(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  if (!requireAuthenticated(checked.session)) return json({ ok: false, message: "Please sign in before changing privacy conditions." }, 401);
  checked.session.privacyAccepted = true;
  console.log("[mock privacy] Updated privacy conditions accepted.");
  return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}

async function bookAppointment(request: Request) {
  const checked = validateSensitiveRequest(request);
  if (checked.error) return checked.error;
  if (!requireAuthenticated(checked.session) || !checked.session.privacyAccepted) {
    return json({ ok: false, message: "Please accept the privacy conditions before confirming an appointment." }, 403);
  }
  checked.session.appointmentBooked = true;
  console.log("[mock appointment] Medication review appointment request confirmed.");
  return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}

/* Single-file accessible SPA. Dynamic text is always assigned through textContent. */
function page(nonce: string, csrf: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#163043;--blue:#075e8d;--pale:#eef7fa;--line:#b9cbd4;--good:#075d43;--warn:#7a4300}
*{box-sizing:border-box} body{margin:0;background:#f5f8f9;color:var(--ink);font:18px/1.52 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#fff;border-bottom:4px solid var(--blue);padding:1rem max(1.2rem,calc((100% - 900px)/2))}
.brand{font-weight:800;font-size:1.2rem} main{max-width:900px;margin:0 auto;padding:1.5rem 1.2rem 4rem}
h1{font-size:2rem;line-height:1.2;margin:.2rem 0 .45rem}h2{font-size:1.35rem;line-height:1.25}p{max-width:68ch}
.progress{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1rem;margin:1.25rem 0}
.progress strong{display:block}.progress ol{display:flex;gap:.45rem;list-style:none;padding:0;margin:.7rem 0 0;flex-wrap:wrap}.progress li{background:#e6edf0;border-radius:99px;padding:.22rem .65rem;font-size:.87rem}.progress li.active{background:var(--blue);color:white}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.35rem;margin:1rem 0;box-shadow:0 1px 2px #1231}
.panel[hidden]{display:none}label{display:block;font-weight:700;margin-top:1rem}input{display:block;width:100%;max-width:560px;font:inherit;padding:.62rem;border:2px solid #718894;border-radius:7px}input:focus,a:focus,button:focus{outline:3px solid #e99b27;outline-offset:3px}button{font:inherit;font-weight:700;background:var(--blue);color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.feedback{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .9rem;margin:1rem 0;min-height:1.6rem}.feedback.error{border-color:var(--warn);background:#fff5e9}.feedback.good{border-color:var(--good);background:#ebf8f1}.small{font-size:.92rem}.help{background:#fff8df;border:1px solid #d8bc64;border-radius:9px;padding:1rem}.logs{background:#12242e;color:#def2ee;border-radius:8px;padding:.8rem;max-height:180px;overflow:auto;font:14px/1.4 ui-monospace,SFMono-Regular,monospace}.logs p{margin:.25rem 0}.hide{display:none!important}@media(max-width:550px){body{font-size:17px}.progress ol{display:block}.progress li{display:inline-block;margin:.15rem}}
</style>
</head>
<body>
<header><div class="brand">Hospital secure account portal</div></header>
<main>
<h1>Password recovery, one calm step at a time</h1>
<p id="nextInstruction">Start by asking for a secure recovery instruction.</p>
<nav class="progress" aria-label="Recovery progress"><strong>Your progress</strong><ol><li id="p1">1. Recovery</li><li id="p2">2. Code</li><li id="p3">3. New password</li><li id="p4">4. Sign in</li><li id="p5">5. Privacy & appointment</li></ol></nav>

<section id="requestPanel" class="panel card" aria-labelledby="requestTitle">
<h2 id="requestTitle">1. Ask for a recovery instruction</h2><p>Enter your email address or account reference. We will not say whether an account is registered.</p>
<form id="requestForm" novalidate><label for="identifier">Email address or account reference</label><input id="identifier" name="identifier" autocomplete="username" maxlength="120" required><button type="submit">Prepare recovery instruction</button></form>
<div id="requestFeedback" class="feedback" aria-live="polite">You can pause at any time. Your progress is saved in this browser session.</div>
<p><a id="deliveryLink" class="hide" href="#verify">Open simulated secure recovery instruction</a></p>
</section>

<section id="verifyPanel" class="panel card" hidden aria-labelledby="verifyTitle">
<h2 id="verifyTitle">2. Confirm your recovery code</h2><p>Open the secure instruction above, or paste/type its code here. There is no rush.</p>
<form id="verifyForm" novalidate><label for="resetCode">Recovery code</label><input id="resetCode" name="resetCode" autocomplete="one-time-code" maxlength="80" required><button type="submit">Confirm code</button></form>
<div id="verifyFeedback" class="feedback" aria-live="polite">Check the code, then select Confirm code.</div>
<button id="backRequest" class="secondary" type="button">Request a new code</button>
</section>

<section id="passwordPanel" class="panel card" hidden aria-labelledby="passwordTitle">
<h2 id="passwordTitle">3. Choose a new password</h2><p>Use 12 or more characters, with an uppercase letter, lowercase letter, number, and symbol.</p>
<form id="passwordForm" novalidate><label for="newPassword">New password</label><input id="newPassword" type="password" autocomplete="new-password" maxlength="128" required><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required><button type="submit">Save new password</button></form>
<div id="passwordFeedback" class="feedback" aria-live="polite">After saving, you will sign in with your new password.</div>
</section>

<section id="loginPanel" class="panel card" hidden aria-labelledby="loginTitle">
<h2 id="loginTitle">4. Sign in</h2><p>Use the same account reference and your new password. We will then ask for one safety code.</p>
<form id="loginForm" novalidate><label for="loginIdentifier">Email address or account reference</label><input id="loginIdentifier" autocomplete="username" maxlength="120" required><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" maxlength="128" required><button type="submit">Sign in securely</button></form>
<div id="loginFeedback" class="feedback" aria-live="polite">You may use password recovery if you need it.</div>
</section>

<section id="mfaPanel" class="panel card" hidden aria-labelledby="mfaTitle">
<h2 id="mfaTitle">Extra safety check</h2><p>Enter the six-digit safety code from your simulated secure message.</p>
<form id="mfaForm" novalidate><label for="mfaCode">Six-digit safety code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button type="submit">Finish sign in</button></form>
<div id="mfaFeedback" class="feedback" aria-live="polite">This code is only for this sign-in session.</div>
</section>

<section id="privacyPanel" class="panel card" hidden aria-labelledby="privacyTitle">
<h2 id="privacyTitle">5. Updated privacy conditions</h2><p>To allow hospital authorities to arrange the medication dosage review, please accept the updated privacy conditions.</p>
<ul><li>Your information is used only for your healthcare and appointment coordination.</li><li>You can ask hospital staff for help with these conditions.</li></ul>
<button id="privacyButton" type="button">I accept the updated privacy conditions</button>
<div id="privacyFeedback" class="feedback" aria-live="polite">Read this at your own pace.</div>
</section>

<section id="appointmentPanel" class="panel card" hidden aria-labelledby="appointmentTitle">
<h2 id="appointmentTitle">Confirm medication review request</h2><p>Your privacy conditions are accepted. Confirm when you are ready.</p><button id="appointmentButton" type="button">Confirm appointment request</button>
<div id="appointmentFeedback" class="feedback" aria-live="polite">No appointment is requested until you select the button.</div>
</section>

<aside class="help" aria-labelledby="helpTitle"><h2 id="helpTitle">Need help or a reminder?</h2><p>You can pause and return without a countdown. For help, contact your usual hospital support channel. Hospital staff will never ask you to send a password or recovery code by email or phone. Check that this page is a secure hospital portal before entering details.</p></aside>
<section class="card" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><p class="small">Simulated delivery and verification messages are shown here for this demonstration.</p><div id="logs" class="logs" aria-live="polite"></div></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
const csrf = ${JSON.stringify(csrf)};
let recoveryToken = "";
let lastIdentifier = localStorage.getItem("hospital-recovery-identifier") || "";
const ids = ["requestPanel","verifyPanel","passwordPanel","loginPanel","mfaPanel","privacyPanel","appointmentPanel"];
const $ = (id) => document.getElementById(id);
const logBox = $("logs");

function addLog(message) {
  console.log(message);
  const line = document.createElement("p");
  line.textContent = message;
  logBox.appendChild(line);
  logBox.scrollTop = logBox.scrollHeight;
}
function feedback(id, text, kind) {
  const item = $(id);
  item.textContent = text;
  item.className = "feedback" + (kind ? " " + kind : "");
}
function show(id) {
  ids.forEach((panel) => { $(panel).hidden = panel !== id; });
}
function progress(number) {
  for (let i = 1; i <= 5; i++) $("p" + i).classList.toggle("active", i === number);
  const notes = [
    "Start by asking for a secure recovery instruction.",
    "Your next step is to confirm your recovery code.",
    "Your next step is to choose a strong new password.",
    "Your next step is to sign in and complete the safety check.",
    "You are almost done: accept privacy conditions, then confirm the appointment request."
  ];
  $("nextInstruction").textContent = notes[number - 1];
}
function choose(panel, number) { show(panel); progress(number); window.scrollTo({top:0,behavior:"smooth"}); }
function safeIdentifier(value) { return /^[a-z0-9@._+\\- ]{3,120}$/i.test(value.trim()); }
function safePassword(value) { return value.length >= 12 && value.length <= 128 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value); }

async function api(path, data) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type":"application/json","X-CSRF-Token":csrf},
    body: JSON.stringify(data)
  });
  let body;
  try { body = await response.json(); } catch { body = {ok:false,message:"The secure portal could not complete that step. Please try again."}; }
  return body;
}
function openVerification() {
  choose("verifyPanel", 2);
  if (recoveryToken) $("resetCode").value = recoveryToken;
}
function route() {
  if (location.hash === "#verify") openVerification();
}
$("identifier").value = lastIdentifier;
$("deliveryLink").addEventListener("click", () => { setTimeout(route, 0); });
window.addEventListener("hashchange", route);

$("requestForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const identifier = $("identifier").value.trim();
  if (!safeIdentifier(identifier)) { feedback("requestFeedback","Enter an email address or account reference using letters, numbers, and common punctuation.","error"); return; }
  localStorage.setItem("hospital-recovery-identifier", identifier);
  lastIdentifier = identifier;
  const result = await api("/api/recovery/request", {identifier});
  feedback("requestFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) {
    recoveryToken = result.testToken || "";
    const link = $("deliveryLink");
    link.href = result.deliveryPath || "#verify";
    link.classList.remove("hide");
    addLog("[mock delivery] Recovery token for testing: " + recoveryToken);
  }
});

$("verifyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = $("resetCode").value.trim();
  if (!/^[A-Za-z0-9_-]{20,}$/.test(token)) { feedback("verifyFeedback","Enter the recovery code from the secure instruction.","error"); return; }
  const result = await api("/api/recovery/verify", {token});
  feedback("verifyFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) setTimeout(() => choose("passwordPanel", 3), 500);
});
$("backRequest").addEventListener("click", () => choose("requestPanel", 1));

$("passwordForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("newPassword").value;
  const confirmPassword = $("confirmPassword").value;
  if (!safePassword(password)) { feedback("passwordFeedback","Use 12+ characters with uppercase, lowercase, number, and symbol.","error"); return; }
  if (password !== confirmPassword) { feedback("passwordFeedback","The two passwords do not match yet.","error"); return; }
  const result = await api("/api/recovery/password", {password,confirmPassword});
  feedback("passwordFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) setTimeout(() => { $("loginIdentifier").value = lastIdentifier; choose("loginPanel", 4); }, 500);
});

$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const identifier = $("loginIdentifier").value.trim();
  const password = $("loginPassword").value;
  if (!safeIdentifier(identifier) || !password) { feedback("loginFeedback","Enter your account reference and password.","error"); return; }
  const result = await api("/api/login", {identifier,password});
  feedback("loginFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) {
    addLog("[mock MFA] Safety code for testing: " + result.testMfaCode);
    setTimeout(() => choose("mfaPanel", 4), 400);
  }
});

$("mfaForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = $("mfaCode").value.trim();
  if (!/^\\d{6}$/.test(code)) { feedback("mfaFeedback","Enter all six digits of the safety code.","error"); return; }
  const result = await api("/api/mfa", {code});
  feedback("mfaFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) setTimeout(() => choose("privacyPanel", 5), 400);
});

$("privacyButton").addEventListener("click", async () => {
  const result = await api("/api/privacy/accept", {});
  feedback("privacyFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) setTimeout(() => { $("privacyPanel").hidden = true; $("appointmentPanel").hidden = false; }, 400);
});
$("appointmentButton").addEventListener("click", async () => {
  const result = await api("/api/appointment", {});
  feedback("appointmentFeedback", result.message, result.ok ? "good" : "error");
  if (result.ok) addLog("[mock appointment] Medication review appointment request confirmed.");
});

(async () => {
  const incoming = new URL(location.href).searchParams.get("reset");
  if (incoming && /^[A-Za-z0-9_-]{20,}$/.test(incoming)) {
    recoveryToken = incoming;
    history.replaceState({}, "", "/#verify");
    addLog("[mock delivery] Secure recovery instruction opened.");
    openVerification();
    return;
  }
  try {
    const response = await fetch("/api/state", {credentials:"same-origin"});
    const state = await response.json();
    if (state.appointmentBooked) { choose("appointmentPanel",5); feedback("appointmentFeedback","Your medication review appointment request is confirmed.","good"); }
    else if (state.authenticated && state.privacyAccepted) { choose("appointmentPanel",5); }
    else if (state.authenticated) { choose("privacyPanel",5); }
    else if (state.needsMfa) { choose("mfaPanel",4); }
    else if (state.recoveryStage === "passwordChanged") { $("loginIdentifier").value=lastIdentifier; choose("loginPanel",4); }
    else if (state.recoveryStage === "verified") choose("passwordPanel",3);
    else if (state.hasReset) choose("verifyPanel",2);
    else choose("requestPanel",1);
  } catch { choose("requestPanel",1); }
  route();
})();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert: CERT, key: KEY },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      /* HTTPS-only listener plus rejection of explicitly forwarded insecure traffic. */
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure HTTPS connection required.", { status: 426, headers: { "Cache-Control": "no-store" } });
      }

      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const isNew = !session;
        if (!session) session = newSession();
        const nonce = randomToken(18);
        return new Response(page(nonce, session.csrf), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            ...secureHeaders(nonce),
            ...(isNew ? { "Set-Cookie": sessionCookie(session.id) } : {}),
          },
        });
      }

      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        if (!session) return json({ ok: false, message: "Please open the secure portal first." }, 401);
        return json(publicState(session));
      }

      if (request.method === "POST" && url.pathname === "/api/recovery/request") return await resetRequest(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/verify") return await verifyReset(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/password") return await replacePassword(request);
      if (request.method === "POST" && url.pathname === "/api/login") return await login(request);
      if (request.method === "POST" && url.pathname === "/api/mfa") return await verifyMfa(request);
      if (request.method === "POST" && url.pathname === "/api/privacy/accept") return await acceptPrivacy(request);
      if (request.method === "POST" && url.pathname === "/api/appointment") return await bookAppointment(request);

      return new Response("Not found.", { status: 404, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    } catch {
      /* Requirement 3: no debug information or stack traces in responses. */
      return new Response("The secure portal could not process that request.", {
        status: 500,
        headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
      });
    }
  },
});

console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
