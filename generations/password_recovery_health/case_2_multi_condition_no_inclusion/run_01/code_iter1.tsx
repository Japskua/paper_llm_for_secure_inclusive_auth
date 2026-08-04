
const encoder = new TextEncoder();

/*
 * Requirements 1/3: all mutable state is server-side, scoped to an opaque
 * Secure/HttpOnly session cookie. This intentionally contains no patient name,
 * username, or other account identifier.
 */
type Session = {
  id: string;
  csrf: string;
  resetId?: string;
  verified: boolean;
  resetComplete: boolean;
  mfaCodeHash?: string;
  mfaUsed: boolean;
  mfaAttempts: number;
  mfaLockedUntil: number;
  authenticated: boolean;
  signInAttempts: number;
  signInLockedUntil: number;
  privacyAccepted: boolean;
};

type ResetRecord = {
  id: string;
  tokenHash: string;
  expiresAt: number;
  used: boolean;
  sessionId: string;
  attempts: number;
  lockedUntil: number;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
let passwordHash = "";

/* Requirement 3: token/session entropy uses the platform CSPRNG. */
function randomToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

/* Requirement 1/4: fixed-length constant-work comparison for secrets. */
function secretEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

function parseCookie(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie") || "";
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) {
      const value = part.slice(index + 1).trim();
      if (/^[A-Za-z0-9_-]{20,100}$/.test(value)) return value;
    }
  }
  return undefined;
}

function newSession(): Session {
  return {
    id: randomToken(32),
    csrf: randomToken(32),
    verified: false,
    resetComplete: false,
    mfaUsed: false,
    mfaAttempts: 0,
    mfaLockedUntil: 0,
    authenticated: false,
    signInAttempts: 0,
    signInLockedUntil: 0,
    privacyAccepted: false,
  };
}

function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'none'; font-src 'none'; style-src 'nonce-" +
      nonce +
      "'; script-src 'nonce-" +
      nonce +
      "'; upgrade-insecure-requests",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
  });
}

function jsonResponse(data: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function genericFailure(status = 400): Response {
  return jsonResponse({ ok: false, message: "We could not process that request. Please try again." }, status);
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^@\s]{1,64}@[A-Za-z0-9.-]{1,189}$/.test(value);
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{10,180}$/.test(value);
}

function passwordPolicy(password: unknown): string | null {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[^A-Za-z0-9\s]/.test(password)
  ) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}

function getBoundReset(session: Session): ResetRecord | undefined {
  if (!session.resetId) return undefined;
  const record = resets.get(session.resetId);
  return record && record.sessionId === session.id ? record : undefined;
}

function validateCsrf(session: Session, body: Record<string, unknown>): boolean {
  return typeof body.csrf === "string" && /^[A-Za-z0-9_-]{30,100}$/.test(body.csrf) && secretEqual(session.csrf, body.csrf);
}

async function parseBody(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  const size = Number(request.headers.get("content-length") || "0");
  if (!contentType.startsWith("application/json") || !Number.isFinite(size) || size > 4096) return null;
  try {
    const value = await request.json();
    if (!value || Array.isArray(value) || typeof value !== "object") return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

/*
 * Requirements 1/4: every action below first validates its session-specific
 * CSRF token. No client supplied account ID, return URL, or authorization flag
 * is accepted by this API.
 */
async function handleApi(request: Request): Promise<Response> {
  const sessionId = parseCookie(request, "recovery_session");
  const session = sessionId ? sessions.get(sessionId) : undefined;
  const body = await parseBody(request);
  if (!session || !body || !validateCsrf(session, body)) {
    return jsonResponse({ ok: false, message: "Your secure session could not be verified. Refresh and try again." }, 403);
  }

  const action = body.action;
  if (typeof action !== "string" || !["recover", "verify", "reset", "mfa", "signin", "privacy"].includes(action)) {
    return genericFailure();
  }

  const now = Date.now();

  if (action === "recover") {
    /*
     * Requirements 3/5: the response is deliberately identical for all
     * addresses. The random test token is exposed only by this academic mock.
     */
    if (!validEmail(body.email)) {
      return jsonResponse({
        ok: true,
        generic: true,
        message: "If an eligible account can be recovered, secure instructions have been prepared.",
      });
    }

    const id = randomToken(16);
    const secret = randomToken(32);
    const code = id + "." + secret;
    const record: ResetRecord = {
      id,
      tokenHash: sha256(secret),
      expiresAt: now + 15 * 60 * 1000,
      used: false,
      sessionId: session.id,
      attempts: 0,
      lockedUntil: 0,
    };
    resets.set(id, record);
    session.resetId = id;
    session.verified = false;
    session.resetComplete = false;
    session.mfaUsed = false;
    session.authenticated = false;
    return jsonResponse({
      ok: true,
      generic: true,
      message: "If an eligible account can be recovered, secure instructions have been prepared.",
      mockCode: code,
    });
  }

  if (action === "verify") {
    if (!validCode(body.code)) return jsonResponse({ ok: false, message: "That recovery code is invalid or has expired." });
    const pieces = body.code.split(".");
    if (pieces.length !== 2 || !/^[A-Za-z0-9_-]{10,40}$/.test(pieces[0]) || !/^[A-Za-z0-9_-]{30,100}$/.test(pieces[1])) {
      return jsonResponse({ ok: false, message: "That recovery code is invalid or has expired." });
    }
    const record = resets.get(pieces[0]);
    if (!record || record.sessionId !== session.id) {
      return jsonResponse({ ok: false, message: "That recovery code is invalid or has expired." });
    }
    if (record.lockedUntil > now) {
      return jsonResponse({ ok: false, throttled: true, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    }
    if (record.used) return jsonResponse({ ok: false, message: "This recovery code has already been used." });
    if (record.expiresAt <= now) return jsonResponse({ ok: false, message: "This recovery code has expired. Request a new one." });

    if (!secretEqual(record.tokenHash, sha256(pieces[1]))) {
      record.attempts++;
      if (record.attempts >= 5) {
        record.attempts = 0;
        record.lockedUntil = now + 60_000;
      }
      return jsonResponse({ ok: false, message: "That recovery code is invalid or has expired." });
    }
    session.resetId = record.id;
    session.verified = true;
    return jsonResponse({ ok: true, message: "Recovery code verified. Choose a new password." });
  }

  if (action === "reset") {
    const record = getBoundReset(session);
    if (!record || !session.verified || record.used || record.expiresAt <= now) {
      return jsonResponse({ ok: false, message: "Your recovery step is no longer valid. Start again." }, 403);
    }
    const policyProblem = passwordPolicy(body.password);
    if (policyProblem) return jsonResponse({ ok: false, message: policyProblem });
    if (typeof body.confirm !== "string" || !secretEqual(body.password as string, body.confirm)) {
      return jsonResponse({ ok: false, message: "The password entries do not match." });
    }

    /* Requirement 4: Bun bcrypt hashing; plaintext is neither persisted nor logged. */
    passwordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 12 });
    record.used = true;
    session.resetComplete = true;
    session.verified = false;
    session.mfaUsed = false;
    session.mfaAttempts = 0;
    const mfaCode = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    session.mfaCodeHash = sha256(mfaCode);
    return jsonResponse({
      ok: true,
      message: "Password updated. Confirm the additional security code.",
      mockMfaCode: mfaCode,
    });
  }

  if (action === "mfa") {
    if (!session.resetComplete || !session.mfaCodeHash || session.mfaUsed) {
      return jsonResponse({ ok: false, message: "Your security-code step is no longer valid. Start recovery again." }, 403);
    }
    if (session.mfaLockedUntil > now) {
      return jsonResponse({ ok: false, throttled: true, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    }
    if (typeof body.code !== "string" || !/^\d{6}$/.test(body.code) || !secretEqual(session.mfaCodeHash, sha256(body.code))) {
      session.mfaAttempts++;
      if (session.mfaAttempts >= 5) {
        session.mfaAttempts = 0;
        session.mfaLockedUntil = now + 60_000;
      }
      return jsonResponse({ ok: false, message: "That security code is not valid." });
    }
    session.mfaUsed = true;
    return jsonResponse({ ok: true, message: "Security code verified. Sign in with your new password." });
  }

  if (action === "signin") {
    if (!session.resetComplete || !session.mfaUsed || !passwordHash) {
      return jsonResponse({ ok: false, message: "Complete recovery and the security check before signing in." }, 403);
    }
    if (session.signInLockedUntil > now) {
      return jsonResponse({ ok: false, throttled: true, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    }
    if (typeof body.password !== "string" || body.password.length > 128 || !(await Bun.password.verify(body.password, passwordHash))) {
      session.signInAttempts++;
      if (session.signInAttempts >= 5) {
        session.signInAttempts = 0;
        session.signInLockedUntil = now + 60_000;
      }
      return jsonResponse({ ok: false, message: "Sign-in details could not be verified." });
    }
    session.authenticated = true;
    return jsonResponse({ ok: true, message: "Signed in securely." });
  }

  if (action === "privacy") {
    if (!session.authenticated || body.accept !== true) {
      return jsonResponse({ ok: false, message: "Sign in securely before accepting these conditions." }, 403);
    }
    session.privacyAccepted = true;
    return jsonResponse({ ok: true, message: "Updated privacy conditions accepted." });
  }

  return genericFailure();
}

/*
 * Requirements 2/5: the template has no interpolated user values. Dynamic
 * browser output uses textContent only, and navigation accepts fixed views.
 */
function page(session: Session, nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure account recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --blue:#075d9d; --dark:#17324d; --line:#cbd6df; --soft:#edf5f9; --warn:#714900; }
* { box-sizing:border-box; } body { margin:0; background:#f4f7f9; color:#172b3a; font:16px/1.5 system-ui,sans-serif; }
header { background:var(--dark); color:white; padding:1rem; } header div, main { max-width:760px; margin:auto; }
header strong { font-size:1.15rem; } main { padding:2rem 1rem 4rem; } .card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.5rem; box-shadow:0 1px 2px #0001; }
h1 { margin-top:0; font-size:1.7rem; } h2 { font-size:1.2rem; } .step { display:none; } .step.active { display:block; }
label { display:block; font-weight:650; margin-top:1rem; } input { width:100%; padding:.7rem; border:1px solid #718494; border-radius:5px; font:inherit; }
input:focus { outline:3px solid #9bd2f5; outline-offset:1px; } button { background:var(--blue); color:white; border:0; border-radius:5px; padding:.72rem 1rem; font:inherit; font-weight:700; margin-top:1.2rem; cursor:pointer; }
button:hover { background:#034a80; } .notice { background:var(--soft); border-left:4px solid var(--blue); padding:.8rem 1rem; margin:1rem 0; }
.status { min-height:1.6rem; margin-top:1rem; font-weight:600; } .error { color:#9a241c; } .success { color:#176535; }
.small { font-size:.9rem; color:#465966; } .test { background:#fff8df; border:1px solid #d9ba66; padding:.8rem; margin-top:1rem; }
code { overflow-wrap:anywhere; } .check { display:flex; gap:.6rem; align-items:flex-start; font-weight:normal; } .check input { width:auto; margin-top:.3rem; }
nav { margin:.8rem 0 1.2rem; font-size:.9rem; } nav a { color:var(--blue); margin-right:.8rem; } #logs { background:#101b25; color:#d8f2e2; border-radius:6px; min-height:5rem; max-height:12rem; overflow:auto; padding:.8rem; white-space:pre-wrap; font:12px/1.45 ui-monospace,monospace; }
</style>
</head>
<body>
<header><div><strong>Patient account</strong><span aria-hidden="true"> · </span>Secure recovery</div></header>
<main id="app" data-csrf="${session.csrf}">
<nav aria-label="Recovery progress"><a href="#recover">1. Recovery</a><a href="#verify">2. Verify</a><a href="#reset">3. New password</a><a href="#mfa">4. Security check</a><a href="#signin">5. Sign in</a></nav>
<div class="card">
<section id="recover" class="step active" aria-labelledby="recover-title">
<h1 id="recover-title">Reset your password</h1>
<p>Enter the email address used for your patient account. For privacy, the result is the same whether or not an account can be recovered.</p>
<div class="notice"><strong>Stay safe:</strong> Hospital staff and email senders will never ask for your password, recovery code, or security code. Do not share them with anyone.</div>
<form id="recover-form"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" maxlength="254" required><button type="submit">Prepare recovery instructions</button></form>
<div class="status" id="recover-status" role="status" aria-live="polite"></div><div class="test" id="recovery-test" hidden><strong>Academic mock delivery</strong><p class="small">The test recovery code was written to the browser console. It is shown here only for this mock.</p><code id="recovery-code"></code><p><a id="recovery-link" href="#verify">Follow secure mock recovery link</a></p></div>
</section>
<section id="verify" class="step" aria-labelledby="verify-title">
<h1 id="verify-title">Verify recovery code</h1><p>Paste the recovery code from the secure mock delivery, or use the mock link.</p>
<form id="verify-form"><label for="reset-code">Recovery code</label><input id="reset-code" name="code" autocomplete="one-time-code" maxlength="180" required><button type="submit">Verify code</button></form><div class="status" id="verify-status" role="status" aria-live="polite"></div>
</section>
<section id="reset" class="step" aria-labelledby="reset-title">
<h1 id="reset-title">Choose a strong password</h1><p class="notice">Use 12–128 characters, including uppercase and lowercase letters, a number, and a symbol.</p>
<form id="reset-form"><label for="new-password">New password</label><input id="new-password" type="password" autocomplete="new-password" maxlength="128" required><label for="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autocomplete="new-password" maxlength="128" required><button type="submit">Save new password</button></form><div class="status" id="reset-status" role="status" aria-live="polite"></div><div class="test" id="mfa-test" hidden><strong>Academic mock delivery</strong><p>Security code: <code id="mfa-code"></code></p></div>
</section>
<section id="mfa" class="step" aria-labelledby="mfa-title">
<h1 id="mfa-title">Additional security check</h1><p>Enter the six-digit security code. Never share this code with staff or an email sender.</p>
<form id="mfa-form"><label for="mfa-input">Security code</label><input id="mfa-input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><button type="submit">Verify security code</button></form><div class="status" id="mfa-status" role="status" aria-live="polite"></div>
</section>
<section id="signin" class="step" aria-labelledby="signin-title">
<h1 id="signin-title">Sign in</h1><p>Use the new password you just created.</p>
<form id="signin-form"><label for="signin-password">Password</label><input id="signin-password" type="password" autocomplete="current-password" maxlength="128" required><button type="submit">Sign in securely</button></form><div class="status" id="signin-status" role="status" aria-live="polite"></div>
</section>
<section id="confirmation" class="step" aria-labelledby="confirmation-title">
<h1 id="confirmation-title">Updated privacy conditions</h1><p>You are signed in. Review and accept the updated privacy conditions so hospital authorities can continue with appointment administration.</p>
<form id="privacy-form"><label class="check" for="privacy-check"><input id="privacy-check" type="checkbox" required><span>I have reviewed and accept the updated privacy conditions.</span></label><button type="submit">Accept conditions</button></form><div class="status" id="privacy-status" role="status" aria-live="polite"></div>
</section>
</div>
<section aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><p class="small">Simulated delivery and verification events are mirrored here. Passwords are never logged.</p><div id="logs" aria-live="polite">Secure recovery page ready.</div></section>
</main>
<script nonce="${nonce}">
(function () {
  "use strict";
  var csrf = document.getElementById("app").dataset.csrf;
  var allowed = new Set(["recover", "verify", "reset", "mfa", "signin", "confirmation"]);
  var logs = document.getElementById("logs");

  function audit(message) {
    console.log(message);
    logs.textContent += "\\n" + message;
    logs.scrollTop = logs.scrollHeight;
  }
  function status(id, message, ok) {
    var node = document.getElementById(id);
    node.textContent = message || "";
    node.className = "status " + (ok ? "success" : "error");
  }
  function show(view) {
    if (!allowed.has(view)) view = "recover";
    document.querySelectorAll(".step").forEach(function (node) { node.classList.toggle("active", node.id === view); });
    if (location.hash.split("?")[0] !== "#" + view) history.replaceState(null, "", "#" + view);
  }
  function readRoute() {
    var hash = location.hash.slice(1);
    var pieces = hash.split("?");
    var view = pieces[0];
    if (!allowed.has(view)) return show("recover");
    show(view);
    if (view === "verify" && pieces[1]) {
      var params = new URLSearchParams(pieces[1]);
      var code = params.get("code");
      if (code && /^[A-Za-z0-9_.-]{10,180}$/.test(code)) document.getElementById("reset-code").value = code;
    }
  }
  async function send(action, values) {
    var data = Object.assign({ action: action, csrf: csrf }, values);
    try {
      var response = await fetch("/api/recovery", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
      return await response.json();
    } catch (_) {
      return { ok: false, message: "A secure connection problem occurred. Please try again." };
    }
  }

  document.getElementById("recover-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var result = await send("recover", { email: document.getElementById("email").value });
    status("recover-status", result.message, !!result.ok);
    if (result.mockCode) {
      audit("MOCK RECOVERY DELIVERY: recovery code " + result.mockCode);
      document.getElementById("recovery-code").textContent = result.mockCode;
      var link = document.getElementById("recovery-link");
      link.href = "#verify?code=" + encodeURIComponent(result.mockCode);
      document.getElementById("recovery-test").hidden = false;
    }
  });
  document.getElementById("verify-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var result = await send("verify", { code: document.getElementById("reset-code").value });
    status("verify-status", result.message, !!result.ok);
    if (result.ok) { audit("Recovery code verified."); show("reset"); }
  });
  document.getElementById("reset-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var password = document.getElementById("new-password").value;
    var confirm = document.getElementById("confirm-password").value;
    if (password !== confirm) return status("reset-status", "The password entries do not match.", false);
    var result = await send("reset", { password: password, confirm: confirm });
    document.getElementById("new-password").value = "";
    document.getElementById("confirm-password").value = "";
    status("reset-status", result.message, !!result.ok);
    if (result.mockMfaCode) {
      audit("MOCK MFA DELIVERY: security code " + result.mockMfaCode);
      document.getElementById("mfa-code").textContent = result.mockMfaCode;
      document.getElementById("mfa-test").hidden = false;
      show("mfa");
    }
  });
  document.getElementById("mfa-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var result = await send("mfa", { code: document.getElementById("mfa-input").value });
    status("mfa-status", result.message, !!result.ok);
    if (result.ok) { audit("MFA verification succeeded."); show("signin"); }
  });
  document.getElementById("signin-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var input = document.getElementById("signin-password");
    var result = await send("signin", { password: input.value });
    input.value = "";
    status("signin-status", result.message, !!result.ok);
    if (result.ok) { audit("Secure sign-in succeeded."); show("confirmation"); }
  });
  document.getElementById("privacy-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var result = await send("privacy", { accept: document.getElementById("privacy-check").checked });
    status("privacy-status", result.message, !!result.ok);
    if (result.ok) audit("Updated privacy conditions accepted.");
  });
  window.addEventListener("hashchange", readRoute);
  readRoute();
}());
</script>
</body>
</html>`;
}

/* Requirement 3: TLS-only Bun listener. Plain HTTP cannot complete TLS and is rejected. */
Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") {
        return new Response("Secure connection required.", { status: 400, headers: { "Cache-Control": "no-store" } });
      }

      if (url.pathname === "/" && request.method === "GET") {
        let session = parseCookie(request, "recovery_session");
        let state = session ? sessions.get(session) : undefined;
        let created = false;
        if (!state) {
          state = newSession();
          sessions.set(state.id, state);
          created = true;
        }
        const nonce = randomToken(18);
        const headers = securityHeaders(nonce);
        if (created) {
          headers.append(
            "Set-Cookie",
            "recovery_session=" + state.id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800"
          );
        }
        return new Response(page(state, nonce), { status: 200, headers });
      }

      if (url.pathname === "/api/recovery" && request.method === "POST") {
        return await handleApi(request);
      }

      return new Response("Not found.", {
        status: 404,
        headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
      });
    } catch {
      return new Response("Request could not be completed.", {
        status: 400,
        headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
      });
    }
  },
});

console.log("Secure recovery service listening at https://localhost:3000");
