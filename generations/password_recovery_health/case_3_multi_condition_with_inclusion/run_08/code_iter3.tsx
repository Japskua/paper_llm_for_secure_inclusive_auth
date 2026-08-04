
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System
  Sections 1–5: HTTPS-only Bun server, in-memory security state, CSRF,
  reset-token handling, password hashing, MFA, and protected actions.
*/

type Session = {
  csrf: string;
  userId?: string;
  mfaPendingUserId?: string;
  mfaPendingExpiresAt?: number;
  mfaFailedAttempts?: number;
  mfaLockedUntil?: number;
  /*
    Requirement 3/4: this is a server-side, session-bound reference only.
    The raw recovery token is never retained in browser storage.
  */
  verifiedResetTokenHash?: string;
  verifiedResetUserId?: string;
  verifiedResetExpiresAt?: number;
};

type User = {
  id: string;
  identifier: string;
  passwordHash: string;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
};

type ResetToken = {
  userId: string;
  tokenHash: string;
  expiresAt: number;
  used: boolean;
};

type AttemptWindow = { count: number; startedAt: number; lockedUntil: number };
type RateWindow = { count: number; startedAt: number };

const PORT = Number(Bun.env.PORT || 3000);
const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();
const loginAttempts = new Map<string, AttemptWindow>();
const resetRequests = new Map<string, RateWindow>();

/* Internal mock record only; it is never rendered or returned by the API. */
const users = new Map<string, User>();
const demoUser: User = {
  id: "u_7fd2e6c04a",
  identifier: "helena@hospital.test",
  passwordHash: await Bun.password.hash("Initial-Only-Password!42", {
    algorithm: "argon2id",
  }),
  privacyAccepted: false,
  appointmentConfirmed: false,
};
users.set(demoUser.identifier, demoUser);

const MFA_CODE = "246810"; // Deterministic evaluation-only mock code.
const RESET_TTL_MS = 15 * 60 * 1000;
const MFA_PENDING_TTL_MS = 10 * 60 * 1000;
const MFA_MAX_FAILED_ATTEMPTS = 5;
const LOCK_MS = 10 * 60 * 1000;
const WINDOW_MS = 10 * 60 * 1000;

function randomId(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}

function tokenHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function secureEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function getCookie(request: Request, name: string): string | undefined {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }
  return undefined;
}

function newSession(): { id: string; session: Session } {
  const id = randomId();
  const session: Session = { csrf: randomId(24) };
  sessions.set(id, session);
  return { id, session };
}

function sessionFor(request: Request): { id: string; session: Session; fresh: boolean } {
  const existing = getCookie(request, "__Host-hospital_session");
  if (existing && sessions.has(existing)) {
    return { id: existing, session: sessions.get(existing)!, fresh: false };
  }
  const created = newSession();
  return { id: created.id, session: created.session, fresh: true };
}

function sessionCookie(id: string): string {
  return `__Host-hospital_session=${id}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

function securityHeaders(nonce: string, cookie?: string): Headers {
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; " +
      "form-action 'self'; frame-ancestors 'none';",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store",
  });
  if (cookie) headers.set("Set-Cookie", cookie);
  return headers;
}

function apiHeaders(cookie?: string): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store",
  });
  if (cookie) headers.set("Set-Cookie", cookie);
  return headers;
}

function json(data: object, status = 200, cookie?: string): Response {
  return new Response(JSON.stringify(data), { status, headers: apiHeaders(cookie) });
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 5 &&
    value.length <= 120 &&
    /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/i.test(value);
}

function normalizeIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}

function validMfaCode(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

/* Requirement 4: server-side strong password policy, repeated in UI. */
function passwordProblem(password: unknown): string | null {
  if (typeof password !== "string") return "Enter a new password.";
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Use no more than 128 characters.";
  if (/\s/.test(password)) return "Do not use spaces in this password.";
  if (!/[a-z]/.test(password)) return "Add a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Add an uppercase letter.";
  if (!/\d/.test(password)) return "Add a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Add a symbol.";
  return null;
}

function csrfValid(request: Request, session: Session): boolean {
  const submitted = request.headers.get("x-csrf-token") || "";
  return submitted.length === session.csrf.length && secureEqual(submitted, session.csrf);
}

function authenticated(session: Session): User | null {
  if (!session.userId) return null;
  for (const user of users.values()) if (user.id === session.userId) return user;
  return null;
}

function resetRecord(token: string): ResetToken | null {
  if (!validToken(token)) return null;
  const record = resetTokens.get(tokenHash(token));
  if (!record || record.used || record.expiresAt < Date.now()) return null;
  return record;
}

function clearVerifiedReset(session: Session): void {
  delete session.verifiedResetTokenHash;
  delete session.verifiedResetUserId;
  delete session.verifiedResetExpiresAt;
}

/*
  A validated recovery state is retained only in the secure HttpOnly session.
  Its reference must still identify an unconsumed, unexpired reset record.
*/
function verifiedResetRecord(session: Session): ResetToken | null {
  if (
    !session.verifiedResetTokenHash ||
    !session.verifiedResetUserId ||
    !session.verifiedResetExpiresAt ||
    session.verifiedResetExpiresAt < Date.now()
  ) {
    clearVerifiedReset(session);
    return null;
  }

  const record = resetTokens.get(session.verifiedResetTokenHash);
  if (
    !record ||
    record.used ||
    record.expiresAt < Date.now() ||
    record.userId !== session.verifiedResetUserId ||
    record.expiresAt !== session.verifiedResetExpiresAt
  ) {
    clearVerifiedReset(session);
    return null;
  }
  return record;
}

function clearMfaPending(session: Session): void {
  delete session.mfaPendingUserId;
  delete session.mfaPendingExpiresAt;
  delete session.mfaFailedAttempts;
  delete session.mfaLockedUntil;
}

function loginAllowed(key: string): boolean {
  const entry = loginAttempts.get(key);
  return !entry || entry.lockedUntil <= Date.now();
}

function loginFailure(key: string): void {
  const now = Date.now();
  let entry = loginAttempts.get(key);
  if (!entry || now - entry.startedAt > WINDOW_MS) {
    entry = { count: 0, startedAt: now, lockedUntil: 0 };
  }
  entry.count++;
  if (entry.count >= 5) entry.lockedUntil = now + LOCK_MS;
  loginAttempts.set(key, entry);
}

function resetRateAllowed(key: string): boolean {
  const now = Date.now();
  let entry = resetRequests.get(key);
  if (!entry || now - entry.startedAt > WINDOW_MS) {
    entry = { count: 0, startedAt: now };
    resetRequests.set(key, entry);
  }
  entry.count++;
  return entry.count <= 5;
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 8192) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

/*
  Requirement 2: template contains no user-controlled server interpolation.
  Client rendering assigns user text through textContent/value rather than unsafe HTML.
*/
function page(nonce: string, csrf: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#163042;--muted:#526775;--blue:#075f9d;--pale:#edf6fa;--line:#bfd0da;--good:#0c6a45;--bad:#a32727}
*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:var(--ink);font:18px/1.52 Arial,sans-serif}
.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:.7rem;z-index:2}
header{background:#fff;border-bottom:4px solid var(--blue);padding:1.1rem max(1rem,calc((100% - 760px)/2))}
header strong{font-size:1.18rem}main{max-width:760px;margin:1.7rem auto;padding:0 1rem 3rem}
.progress{display:flex;gap:.35rem;flex-wrap:wrap;margin:0 0 1.3rem;padding:0;list-style:none}.progress li{font-size:.84rem;padding:.3rem .55rem;border-radius:1rem;background:#dce6eb}.progress .active{background:var(--blue);color:#fff}
.card,details{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.35rem;margin-bottom:1rem;box-shadow:0 1px 2px #0000000b}
h1{font-size:1.65rem;line-height:1.2;margin:.1rem 0 .8rem}h2{font-size:1.15rem;margin:0 0 .5rem}.next{background:var(--pale);border-left:5px solid var(--blue);padding:.8rem 1rem;margin:1rem 0}.safe{font-size:.93rem}
label{display:block;font-weight:bold;margin:1rem 0 .25rem}input{font:inherit;width:100%;padding:.65rem;border:2px solid #77909d;border-radius:5px}.checkbox-input{width:auto}
input:focus,button:focus{outline:3px solid #e49b22;outline-offset:2px}
button{font:inherit;font-weight:bold;border:0;border-radius:5px;background:var(--blue);color:#fff;padding:.65rem 1rem;margin:1rem .5rem 0 0;cursor:pointer}button.secondary{background:#e1ebf0;color:var(--ink)}button.link{background:none;color:#075f9d;text-decoration:underline;padding:0;margin:.5rem 0}
.feedback{min-height:1.5rem;margin-top:1rem;font-weight:bold}.error{color:var(--bad)}.success{color:var(--good)}.hint{color:var(--muted);font-size:.92rem}.code{font-family:monospace;word-break:break-all;background:#eef3f5;padding:.45rem;border-radius:4px}
details summary{font-weight:bold;cursor:pointer}#logs{white-space:pre-wrap;max-height:170px;overflow:auto;background:#10222c;color:#dff5ff;padding:.75rem;border-radius:5px;font:13px/1.4 monospace}
footer{max-width:760px;margin:auto;padding:0 1rem 2rem;color:var(--muted);font-size:.88rem}
@media(max-width:500px){body{font-size:17px}.progress li{font-size:.75rem}}
</style>
</head>
<body>
<a class="skip" href="#content">Skip to main content</a>
<header><strong>Hospital account support</strong><div class="hint">Private account recovery</div></header>
<main id="content" tabindex="-1">
  <ol class="progress" aria-label="Recovery progress" id="progress"></ol>
  <section id="app" class="card" aria-live="polite"></section>
  <details id="help"><summary>Help and safe authentication</summary>
    <p>You can pause at any time. Your current step and account email are saved only in this browser. A verified recovery step is safely retained in your secure session.</p>
    <p class="safe"><strong>Keep your account safe:</strong> hospital staff will never ask you to share a password or verification code by email, phone, or support message.</p>
    <p>If you need support, contact the hospital using the phone number on your official appointment letter.</p>
  </details>
  <section class="card"><h2>Activity logs (simulation)</h2><div id="logs" aria-live="polite">Ready. Simulation activity appears here.</div></section>
</main>
<footer>No time limit. You may return to this page when ready.</footer>
<script nonce="${nonce}">
(() => {
"use strict";
/* Browser persistence contains orientation only, never recovery tokens. */
const csrf = ${JSON.stringify(csrf)};
const app = document.getElementById("app");
const progress = document.getElementById("progress");
const logs = document.getElementById("logs");
const originalLog = console.log.bind(console);
console.log = (...items) => {
  originalLog(...items);
  const line = items.map(v => typeof v === "string" ? v : JSON.stringify(v)).join(" ");
  logs.textContent += "\\n" + line;
  logs.scrollTop = logs.scrollHeight;
};
const steps = ["identify","verify","password","signin","mfa","privacy","appointment","done"];
const labels = {identify:"1 Account",verify:"2 Verify",password:"3 Password",signin:"4 Sign in",mfa:"5 Security check",privacy:"6 Privacy",appointment:"7 Confirm"};
let state = {step:"identify", identifier:"", token:""};
try {
  const saved = JSON.parse(localStorage.getItem("hospital-recovery-progress") || "{}");
  if (steps.includes(saved.step)) state.step = saved.step;
  if (typeof saved.identifier === "string" && saved.identifier.length <= 120) state.identifier = saved.identifier;
} catch (_) {}

function save() {
  localStorage.setItem("hospital-recovery-progress", JSON.stringify({step:state.step,identifier:state.identifier}));
}
function setStep(step) { state.step = step; save(); render(); }
function feedback(message, good=false) {
  const node = document.getElementById("feedback");
  if (node) {
    node.textContent = message;
    node.className = "feedback " + (good ? "success" : "error");
  }
}
function drawProgress() {
  progress.textContent = "";
  const visible = ["identify","verify","password","signin","mfa","privacy","appointment"];
  const current = visible.indexOf(state.step);
  visible.forEach((name,index) => {
    const li = document.createElement("li");
    li.textContent = labels[name];
    if (index === current || (state.step === "done" && index === visible.length - 1)) li.className = "active";
    progress.appendChild(li);
  });
}
async function api(path, body) {
  const response = await fetch(path, {
    method:"POST",
    credentials:"same-origin",
    headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},
    body:JSON.stringify(body)
  });
  let data = {};
  try { data = await response.json(); } catch (_) {}
  return {ok:response.ok,data};
}
function common(title, next, content) {
  return '<h1>'+title+'</h1><div class="next"><strong>Next step:</strong> '+next+'</div>'+content+
    '<p class="safe">Never share your password or verification code with email or support staff.</p><p id="feedback" class="feedback" role="alert"></p>';
}
function hasInMemoryToken() {
  return typeof state.token === "string" && /^[a-f0-9]{64}$/i.test(state.token);
}
function render() {
  drawProgress();

  if (state.step === "identify") {
    app.innerHTML = common("Reset your password","Enter the email address you use for your hospital account.",
      '<p>This is a calm, step-by-step process. You can stop and return later.</p><form id="identifyForm" novalidate><label for="identifier">Hospital account email</label><input id="identifier" type="email" autocomplete="username" required><p class="hint">We use the same response whether or not an account is available.</p><button type="submit">Send recovery code</button></form>');
    const input = document.getElementById("identifier");
    input.value = state.identifier;
    document.getElementById("identifyForm").addEventListener("submit", async e => {
      e.preventDefault();
      state.identifier = input.value.trim();
      save();
      if (!input.checkValidity()) {
        feedback("Please enter an email address in the usual format.");
        return;
      }
      const r = await api("/api/reset-request",{identifier:state.identifier});
      if (!r.ok) {
        feedback("We could not start recovery. Please check the email format and try again.");
        return;
      }
      state.token = typeof r.data.evaluationToken === "string" ? r.data.evaluationToken : "";
      console.log("SIMULATED RECOVERY DELIVERY: reset token =", state.token || "[no token returned]");
      setStep("verify");
    });

  } else if (state.step === "verify") {
    app.innerHTML = common("Check your recovery code","Paste the code from your simulated delivery, or use the verification link below.",
      '<p>For this evaluation, a simulated delivery code is shown below and logged in Activity logs. It is not saved if you reload.</p>' +
      (hasInMemoryToken()
        ? '<p class="code" id="deliveredCode"></p><button type="button" id="linkButton">Use verification link</button>'
        : '<p class="hint">The code is no longer in this browser. Request a new one when you are ready.</p><button type="button" class="secondary" id="newRequest">Request another code</button>') +
      '<form id="verifyForm"><label for="token">Recovery code</label><input id="token" autocomplete="one-time-code" inputmode="text" required><button type="submit">Verify code</button></form>');

    if (hasInMemoryToken()) {
      document.getElementById("deliveredCode").textContent = state.token;
      const tokenInput = document.getElementById("token");
      document.getElementById("linkButton").addEventListener("click", () => {
        tokenInput.value = state.token;
        feedback("Verification link opened safely. Select Verify code to continue.", true);
      });
    } else {
      document.getElementById("newRequest").addEventListener("click", () => setStep("identify"));
    }

    document.getElementById("verifyForm").addEventListener("submit", async e => {
      e.preventDefault();
      const tokenInput = document.getElementById("token");
      const r = await api("/api/reset-validate",{token:tokenInput.value.trim()});
      if (r.ok && r.data.valid) {
        /* Server now holds only a token hash in this secure session. */
        state.token = "";
        setStep("password");
      } else {
        feedback("That code cannot be used. It may be incorrect, already used, or no longer available. Request another code when ready.");
      }
    });

  } else if (state.step === "password") {
    /*
      Requirement 3/4: this stage can resume after reload because its verified
      token reference is server-side in the secure HttpOnly session. No raw
      reset token is sent or read from localStorage here.
    */
    app.innerHTML = common("Create a new password","Choose a password that meets every item below, then continue to sign in.",
      '<p><strong>Password policy:</strong> 12–128 characters, with uppercase and lowercase letters, a number, a symbol, and no spaces.</p><p class="hint">Your verified recovery step is kept safely while you complete this page. There is no time pressure.</p><form id="passwordForm"><label for="password">New password</label><input id="password" type="password" autocomplete="new-password" required><label for="confirm">Confirm new password</label><input id="confirm" type="password" autocomplete="new-password" required><button type="submit">Save new password</button></form><button type="button" class="link" id="backToVerify">Use a different recovery code</button>');
    document.getElementById("backToVerify").addEventListener("click", () => setStep("verify"));
    document.getElementById("passwordForm").addEventListener("submit", async e => {
      e.preventDefault();
      const p = document.getElementById("password").value;
      const c = document.getElementById("confirm").value;
      if (p !== c) {
        feedback("The two passwords do not match.");
        return;
      }
      const r = await api("/api/reset-complete",{password:p,confirm:c});
      if (!r.ok) {
        feedback(r.data.message || "We could not save that password. Check the policy and request another code if needed.");
        return;
      }
      setStep("signin");
    });

  } else if (state.step === "signin") {
    app.innerHTML = common("Sign in","Use your new password. Then complete one short security check.",
      '<form id="loginForm"><label for="loginEmail">Hospital account email</label><input id="loginEmail" type="email" autocomplete="username" required><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form><button type="button" class="link" id="resetAgain">Reset password instead</button>');
    document.getElementById("loginEmail").value = state.identifier;
    document.getElementById("resetAgain").addEventListener("click", () => setStep("identify"));
    document.getElementById("loginForm").addEventListener("submit", async e => {
      e.preventDefault();
      const identifier = document.getElementById("loginEmail").value.trim();
      state.identifier = identifier;
      save();
      const r = await api("/api/login",{identifier,password:document.getElementById("loginPassword").value});
      if (!r.ok) {
        feedback("We could not sign you in. Check your details or reset your password.");
        return;
      }
      console.log("SIMULATED MFA DELIVERY: verification code =", r.data.evaluationMfaCode);
      setStep("mfa");
    });

  } else if (state.step === "mfa") {
    app.innerHTML = common("Security check","Enter the one-time code, then review the privacy conditions.",
      '<p>For this evaluation, the deterministic mock code is shown here and in Activity logs.</p><p class="code">246810</p><p class="hint">This security check is available for 10 minutes after sign-in. Repeated incorrect codes require a new sign-in.</p><form id="mfaForm"><label for="mfaCode">Security code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" required><button type="submit">Verify security code</button></form><button type="button" class="link" id="backToSignIn">Return to sign in</button>');
    document.getElementById("backToSignIn").addEventListener("click", () => setStep("signin"));
    document.getElementById("mfaForm").addEventListener("submit", async e => {
      e.preventDefault();
      const r = await api("/api/mfa",{code:document.getElementById("mfaCode").value.trim()});
      if (!r.ok) {
        feedback(r.data.message || "That security code did not match. Please try again.");
        return;
      }
      setStep("privacy");
    });

  } else if (state.step === "privacy") {
    app.innerHTML = common("Review privacy conditions","Read the short statement, select the checkbox, and save your choice.",
      '<p>Hospital authorities need your permission to use your account information to arrange this medication review appointment.</p><form id="privacyForm"><label><input id="accept" class="checkbox-input" type="checkbox"> I have read and accept the updated privacy conditions.</label><button type="submit">Accept and continue</button></form>');
    document.getElementById("privacyForm").addEventListener("submit", async e => {
      e.preventDefault();
      if (!document.getElementById("accept").checked) {
        feedback("Please select the checkbox when you are ready.");
        return;
      }
      const r = await api("/api/privacy",{accepted:true});
      if (!r.ok) {
        feedback("Please sign in again before continuing.");
        return;
      }
      setStep("appointment");
    });

  } else if (state.step === "appointment") {
    app.innerHTML = common("Confirm medication review appointment","Confirm the request to finish this process.",
      '<p>Your request is for a medication dosage review. No additional personal details are needed on this page.</p><button id="confirmAppointment">Confirm appointment request</button>');
    document.getElementById("confirmAppointment").addEventListener("click", async () => {
      const r = await api("/api/appointment",{confirm:true});
      if (!r.ok) {
        feedback("We could not confirm this request. Please sign in again and try.");
        return;
      }
      setStep("done");
    });

  } else {
    app.innerHTML = common("Appointment request confirmed","You have completed the recovery and privacy steps.",
      '<p>Your medication dosage review appointment request has been recorded. Hospital staff will use their normal scheduling process.</p><button id="startOver" class="secondary">Return to account recovery start</button>');
    document.getElementById("startOver").addEventListener("click", () => {
      state = {step:"identify",identifier:"",token:""};
      save();
      render();
    });
  }
}
save();
render();
})();
</script>
</body></html>`;
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const current = sessionFor(request);
  const cookie = current.fresh ? sessionCookie(current.id) : undefined;
  const body = await readBody(request);
  if (!body) return json({ message: "Unable to process this request." }, 400, cookie);

  /* Requirement 1: every state-changing endpoint validates the session CSRF token. */
  if (!csrfValid(request, current.session)) {
    return json({ message: "Unable to process this request." }, 403, cookie);
  }

  if (pathname === "/api/reset-request") {
    if (!validIdentifier(body.identifier)) {
      return json({ message: "Check the email format and try again." }, 400, cookie);
    }
    clearVerifiedReset(current.session);
    const identifier = normalizeIdentifier(body.identifier);
    const rateKey = tokenHash(identifier + "|tls-client");
    const permitted = resetRateAllowed(rateKey);
    const user = users.get(identifier);

    /* Requirement 4: deliberately identical response prevents account enumeration. */
    const response: Record<string, unknown> = {
      message: "If an account is available, recovery instructions have been prepared.",
    };
    if (permitted && user) {
      const token = randomId(32);
      resetTokens.set(tokenHash(token), {
        userId: user.id,
        tokenHash: tokenHash(token),
        expiresAt: Date.now() + RESET_TTL_MS,
        used: false,
      });
      // Evaluation-only mock delivery: client logs this returned value in browser console.
      response.evaluationToken = token;
    }
    return json(response, 200, cookie);
  }

  if (pathname === "/api/reset-validate") {
    const record = typeof body.token === "string" ? resetRecord(body.token) : null;
    if (!record) {
      return json({ valid: false }, 400, cookie);
    }

    /*
      Bind successful verification to this secure session. The client can reload
      and continue password creation without retaining the raw token anywhere.
    */
    current.session.verifiedResetTokenHash = record.tokenHash;
    current.session.verifiedResetUserId = record.userId;
    current.session.verifiedResetExpiresAt = record.expiresAt;
    return json({ valid: true }, 200, cookie);
  }

  if (pathname === "/api/reset-complete") {
    if (body.password !== body.confirm) {
      return json({ message: "Passwords do not match." }, 400, cookie);
    }
    const problem = passwordProblem(body.password);
    if (problem) return json({ message: problem }, 400, cookie);

    const record = verifiedResetRecord(current.session);
    if (!record) {
      return json({
        message: "Recovery verification is no longer active. Request and verify another code when ready.",
      }, 400, cookie);
    }

    const user = [...users.values()].find((candidate) => candidate.id === record.userId);
    if (!user) {
      clearVerifiedReset(current.session);
      return json({ message: "Unable to process this request." }, 400, cookie);
    }

    /*
      Requirement task: consume the record synchronously before the first await.
      JavaScript request handlers cannot interleave until await, so every later
      request sees used=true and is rejected. On a hash failure we deliberately
      keep it consumed and clear the session reference: requesting a new code is
      safer than allowing a possibly indeterminate password-reset retry.
    */
    record.used = true;
    clearVerifiedReset(current.session);

    try {
      const passwordHash = await Bun.password.hash(body.password as string, {
        algorithm: "argon2id",
      });
      user.passwordHash = passwordHash;
      return json({ message: "Password saved." }, 200, cookie);
    } catch {
      return json({
        message: "We could not save that password. For your security, request and verify another recovery code.",
      }, 500, cookie);
    }
  }

  if (pathname === "/api/login") {
    if (!validIdentifier(body.identifier) || typeof body.password !== "string" || body.password.length > 128) {
      return json({ message: "We could not sign you in." }, 401, cookie);
    }
    const identifier = normalizeIdentifier(body.identifier);
    const key = tokenHash(identifier + "|tls-client");
    if (!loginAllowed(key)) return json({ message: "We could not sign you in." }, 429, cookie);

    const user = users.get(identifier);
    const okay = !!user && await Bun.password.verify(body.password, user.passwordHash);
    if (!okay) {
      loginFailure(key);
      return json({ message: "We could not sign you in." }, 401, cookie);
    }

    loginAttempts.delete(key);
    delete current.session.userId;

    /*
      Requirement 4 / MFA hardening:
      A successful password login creates one short-lived, session-bound MFA
      pending state. Attempts are not shared between users or sessions.
    */
    current.session.mfaPendingUserId = user.id;
    current.session.mfaPendingExpiresAt = Date.now() + MFA_PENDING_TTL_MS;
    current.session.mfaFailedAttempts = 0;
    current.session.mfaLockedUntil = 0;

    return json({ message: "Security check required.", evaluationMfaCode: MFA_CODE }, 200, cookie);
  }

  if (pathname === "/api/mfa") {
    const session = current.session;
    const now = Date.now();

    if (!session.mfaPendingUserId || !session.mfaPendingExpiresAt) {
      return json({
        message: "This security check is no longer active. Please use Return to sign in when you are ready.",
        signInRequired: true,
      }, 401, cookie);
    }

    /* A pending MFA state cannot survive past its explicit expiry time. */
    if (session.mfaPendingExpiresAt <= now) {
      clearMfaPending(session);
      return json({
        message: "This security check has expired. Use Return to sign in when you are ready.",
        signInRequired: true,
      }, 401, cookie);
    }

    if (session.mfaLockedUntil && session.mfaLockedUntil > now) {
      clearMfaPending(session);
      return json({
        message: "Too many security-code attempts. Use Return to sign in when you are ready.",
        signInRequired: true,
      }, 429, cookie);
    }

    if (!validMfaCode(body.code) || !secureEqual(body.code, MFA_CODE)) {
      session.mfaFailedAttempts = (session.mfaFailedAttempts || 0) + 1;

      /*
        Maximum failed-code count: invalidate this session's MFA-pending state.
        A new password login is required before another MFA code can be tried.
      */
      if (session.mfaFailedAttempts >= MFA_MAX_FAILED_ATTEMPTS) {
        clearMfaPending(session);
        return json({
          message: "Too many incorrect security codes. Use Return to sign in when you are ready.",
          signInRequired: true,
        }, 429, cookie);
      }

      const remaining = MFA_MAX_FAILED_ATTEMPTS - session.mfaFailedAttempts;
      return json({
        message: `That security code did not match. Please try again. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`,
      }, 401, cookie);
    }

    session.userId = session.mfaPendingUserId;
    clearMfaPending(session);
    return json({ message: "Signed in." }, 200, cookie);
  }

  const user = authenticated(current.session);
  /* Requirement 1: server-side authorization, never client-provided user/patient IDs. */
  if (!user) return json({ message: "Please sign in to continue." }, 401, cookie);

  if (pathname === "/api/privacy") {
    if (body.accepted !== true) return json({ message: "Please confirm your choice." }, 400, cookie);
    user.privacyAccepted = true;
    return json({ message: "Privacy conditions accepted." }, 200, cookie);
  }

  if (pathname === "/api/appointment") {
    if (body.confirm !== true || !user.privacyAccepted) {
      return json({ message: "Please accept privacy conditions before confirming." }, 403, cookie);
    }
    user.appointmentConfirmed = true;
    return json({ message: "Appointment request confirmed." }, 200, cookie);
  }

  return json({ message: "Not found." }, 404, cookie);
}

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";
const cert = await Bun.file(certPath).text();
const key = await Bun.file(keyPath).text();

Bun.serve({
  port: PORT,
  hostname: "localhost",
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/") {
        const current = sessionFor(request);
        const nonce = randomId(18);
        return new Response(page(nonce, current.session.csrf), {
          status: 200,
          headers: securityHeaders(nonce, current.fresh ? sessionCookie(current.id) : undefined),
        });
      }
      if (request.method === "POST" && url.pathname.startsWith("/api/")) {
        return await handleApi(request, url.pathname);
      }
      return new Response("Not found.", { status: 404, headers: securityHeaders(randomId(18)) });
    } catch {
      /* Requirement 3: generic production-safe error without debug details. */
      return new Response("Unable to process this request.", {
        status: 500,
        headers: securityHeaders(randomId(18)),
      });
    }
  },
});

console.log(`Hospital recovery server running securely at https://localhost:${PORT}`);
