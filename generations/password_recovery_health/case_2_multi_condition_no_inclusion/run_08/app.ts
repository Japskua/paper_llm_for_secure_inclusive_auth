
const sessions = new Map<string, Session>();

type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  resetTokenHash?: string;
  resetExpiresAt?: number;
  resetUsed: boolean;
  verifiedResetAuthorization?: string;
  verifiedResetAuthorizationExpiresAt?: number;
  resetFailures: number;
  resetBlockedUntil: number;
  passwordHash?: string;
  passwordSet: boolean;
  mfaCodeHash?: string;
  mfaCodeExpiresAt?: number;
  mfaCodeUsed: boolean;
  mfaVerified: boolean;
  mfaFailures: number;
  mfaBlockedUntil: number;
  privacyAccepted: boolean;
};

const PORT = 3000;
const SESSION_LIFETIME_MS = 30 * 60 * 1000;
const RESET_LIFETIME_MS = 10 * 60 * 1000;
const VERIFIED_RESET_AUTH_LIFETIME_MS = 5 * 60 * 1000;
const MFA_CODE_LIFETIME_MS = 5 * 60 * 1000;
const THROTTLE_MS = 60 * 1000;
const MFA_CODE = "482915";

/* Requirements 1, 3: cryptographically random per-session IDs, CSRF values, reset tokens, and reset authorizations. */
function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("hex");
}

function safeEqual(left: string | undefined, right: string): boolean {
  if (!left || left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

/* Requirement 3: sessions have an absolute, server-enforced 30-minute expiry. */
function getSession(request: Request): Session | undefined {
  const sid = parseCookies(request).sid;
  if (!sid) return undefined;
  const session = sessions.get(sid);
  if (!session) return undefined;
  if (Date.now() >= session.expiresAt) {
    sessions.delete(sid);
    return undefined;
  }
  return session;
}

function createSession(): Session {
  const id = randomValue();
  const session: Session = {
    id,
    csrf: randomValue(),
    expiresAt: Date.now() + SESSION_LIFETIME_MS,
    resetUsed: false,
    resetFailures: 0,
    resetBlockedUntil: 0,
    passwordSet: false,
    mfaCodeUsed: false,
    mfaVerified: false,
    mfaFailures: 0,
    mfaBlockedUntil: 0,
    privacyAccepted: false,
  };
  sessions.set(id, session);
  return session;
}

/* Requirement 4: MFA state exists only after password creation and is invalidated on all recovery restarts. */
function clearMfaState(session: Session): void {
  session.mfaCodeHash = undefined;
  session.mfaCodeExpiresAt = undefined;
  session.mfaCodeUsed = false;
  session.mfaVerified = false;
  session.mfaFailures = 0;
  session.mfaBlockedUntil = 0;
}

/* Reset recovery state whenever recovery is issued or restarted. */
function clearRecoveryState(session: Session): void {
  session.resetTokenHash = undefined;
  session.resetExpiresAt = undefined;
  session.resetUsed = false;
  session.verifiedResetAuthorization = undefined;
  session.verifiedResetAuthorizationExpiresAt = undefined;
  session.resetFailures = 0;
  session.resetBlockedUntil = 0;
  clearMfaState(session);
}

function verifiedResetAuthorizationCurrentlyValid(session: Session): boolean {
  return Boolean(
    session.verifiedResetAuthorization &&
    session.verifiedResetAuthorizationExpiresAt &&
    Date.now() < session.verifiedResetAuthorizationExpiresAt
  );
}

function mfaCodeCurrentlyValid(session: Session): boolean {
  return Boolean(
    session.mfaCodeHash &&
    session.mfaCodeExpiresAt &&
    !session.mfaCodeUsed &&
    Date.now() < session.mfaCodeExpiresAt
  );
}

/* Requirements 1 and 3: restrictive security headers and HTTPS-only cookie handling. */
function securityHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'self'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self'; upgrade-insecure-requests`
  );
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Pragma", "no-cache");
  return headers;
}

function jsonResponse(data: Record<string, unknown>, status = 200): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message = "Unable to complete that request.", status = 400): Response {
  return jsonResponse({ ok: false, message }, status);
}

/* Requirements 1 and 4: all state-changing API routes require same-session CSRF validation. */
function requireCsrf(request: Request, session: Session | undefined): Response | undefined {
  if (!session) return errorResponse("Your secure session has ended. Please start again.", 401);
  const supplied = request.headers.get("x-csrf-token") || "";
  if (!safeEqual(session.csrf, supplied)) {
    return errorResponse("Your secure session could not be verified. Please refresh and try again.", 403);
  }
  return undefined;
}

async function readJson(request: Request): Promise<Record<string, unknown> | undefined> {
  const contentType = request.headers.get("content-type") || "";
  const length = Number(request.headers.get("content-length") || "0");
  if (!contentType.includes("application/json") || length > 4096) return undefined;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

/* Requirements 2 and 5: inputs are allowlisted, never HTML-interpolated, and never used as outgoing URLs. */
function validAccountInput(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9 .@+()_-]{3,120}$/.test(value);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 12
    && value.length <= 128
    && !/\s/.test(value)
    && /[a-z]/.test(value)
    && /[A-Z]/.test(value)
    && /\d/.test(value)
    && /[^A-Za-z0-9]/.test(value);
}

const html = (csrf: string, nonce: string) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${csrf}">
  <title>Hospital Account Recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --navy:#16355b; --blue:#1769aa; --pale:#eef6fc; --ink:#17212b; --danger:#a32222; --line:#c7d4df; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f4f7fa; color:var(--ink); font:17px/1.5 Arial, sans-serif; }
    header { background:var(--navy); color:white; padding:1.25rem; }
    header div, main, footer { max-width:760px; margin:auto; }
    header h1 { font-size:1.35rem; margin:0; }
    header p { margin:.2rem 0 0; font-size:.95rem; }
    main { padding:1.5rem 1rem 2rem; }
    section { background:white; border:1px solid var(--line); border-radius:10px; padding:1.4rem; box-shadow:0 1px 3px #0012; }
    [hidden] { display:none !important; }
    h2 { margin-top:0; color:var(--navy); }
    label { display:block; font-weight:bold; margin:1rem 0 .3rem; }
    input { width:100%; padding:.72rem; border:1px solid #718397; border-radius:5px; font:inherit; }
    input:focus { outline:3px solid #8cc9ef; outline-offset:1px; }
    button { margin-top:1.2rem; padding:.72rem 1rem; background:var(--blue); border:0; border-radius:5px; color:white; font:inherit; font-weight:bold; cursor:pointer; }
    button.secondary { background:white; color:var(--navy); border:1px solid var(--navy); margin-left:.5rem; }
    button:disabled { opacity:.55; cursor:wait; }
    .notice { background:var(--pale); border-left:4px solid var(--blue); padding:.8rem; }
    .error { color:var(--danger); font-weight:bold; min-height:1.5em; }
    .small { font-size:.92rem; }
    .check { display:flex; align-items:flex-start; gap:.6rem; font-weight:normal; }
    .check input { width:auto; margin-top:.35rem; }
    #logs { margin-top:1.25rem; background:#101923; color:#d7f2df; border-radius:8px; padding:1rem; }
    #logs h2 { color:white; font-size:1rem; margin:0 0:.5rem; }
    #logOutput { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font:13px/1.4 ui-monospace, monospace; }
    footer { padding:0 1rem 2rem; font-size:.88rem; color:#415466; }
    a { color:#075c9f; }
  </style>
  <script src="/client.js" defer></script>
</head>
<body>
  <header><div><h1>Hospital Account Recovery</h1><p>Secure account access for accepting updated privacy conditions</p></div></header>
  <main>
    <section id="recoverStage">
      <h2>Reset your password</h2>
      <p class="notice">For your safety, we give the same response for every account request. Never share a password, recovery link, or security code with anyone — hospital staff will not ask for them by email or phone.</p>
      <form id="recoverForm">
        <label for="account">Email address or account reference</label>
        <input id="account" name="account" autocomplete="username" maxlength="120" required>
        <p class="small">Enter only the address or reference you use to sign in. Do not enter health or appointment details.</p>
        <p class="error" id="recoverError" aria-live="polite"></p>
        <button type="submit">Send recovery instructions</button>
      </form>
      <p><button class="secondary" type="button" id="manualButton">I have a recovery code</button></p>
    </section>

    <section id="verifyStage" hidden>
      <h2>Verify recovery code</h2>
      <p>Open a recovery link only if you requested it. You may also enter the code from the simulated delivery below.</p>
      <form id="verifyForm">
        <label for="token">Recovery code</label>
        <input id="token" name="token" autocomplete="one-time-code" maxlength="128" required>
        <p class="error" id="verifyError" aria-live="polite"></p>
        <button type="submit">Verify code</button>
        <button class="secondary" type="button" data-stage="recover">Back</button>
      </form>
    </section>

    <section id="passwordStage" hidden>
      <h2>Create a strong password</h2>
      <p class="notice">Use at least 12 characters, including uppercase and lowercase letters, a number, and a symbol. Spaces are not permitted.</p>
      <form id="passwordForm">
        <label for="password">New password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" maxlength="128" required>
        <label for="confirmPassword">Confirm new password</label>
        <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required>
        <p class="error" id="passwordError" aria-live="polite"></p>
        <button type="submit">Save new password</button>
      </form>
    </section>

    <section id="mfaStage" hidden>
      <h2>Security code verification</h2>
      <p>A one-time simulated security code has been delivered. It is available in the secure activity log for this evaluation.</p>
      <form id="mfaForm">
        <label for="mfaCode">Security code</label>
        <input id="mfaCode" name="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
        <p class="error" id="mfaError" aria-live="polite"></p>
        <button type="submit">Verify security code</button>
      </form>
    </section>

    <section id="privacyStage" hidden>
      <h2>Updated privacy conditions</h2>
      <p>Your account access has been confirmed. Please review and accept the updated conditions so hospital authorities may arrange your requested medication review appointment.</p>
      <ul>
        <li>Your health information is accessed only for care and administrative purposes.</li>
        <li>You can ask the hospital about privacy choices through verified official channels.</li>
        <li>Never send passwords or verification codes in an email.</li>
      </ul>
      <form id="privacyForm">
        <label class="check" for="privacyCheck"><input id="privacyCheck" type="checkbox" required> <span>I have reviewed and accept the updated privacy conditions.</span></label>
        <p class="error" id="privacyError" aria-live="polite"></p>
        <button type="submit">Accept conditions</button>
      </form>
    </section>

    <section id="confirmationStage" hidden>
      <h2>Privacy conditions accepted</h2>
      <p class="notice">Thank you. Your acceptance has been securely recorded. Hospital authorities can now continue the appointment booking process.</p>
      <p><button type="button" id="startOver">Return to recovery start</button></p>
    </section>

    <aside id="logs" aria-label="Simulated delivery logs">
      <h2>Secure activity log (evaluation simulation)</h2>
      <pre id="logOutput">Ready. Simulated delivery messages will appear here and in the browser console.</pre>
    </aside>
  </main>
  <footer>Check that the address bar shows <strong>https://localhost:${PORT}</strong> before entering credentials. This portal does not contact external services.</footer>
</body>
</html>`;

/* Requirement 2: client logic is a same-origin resource, permitted by CSP script-src 'self'; no inline script is used. */
const clientJs = String.raw`(() => {
  "use strict";

  const csrfElement = document.querySelector('meta[name="csrf-token"]');
  const csrf = csrfElement ? csrfElement.getAttribute("content") : "";
  const stages = ["recover", "verify", "password", "mfa", "privacy", "confirmation"];
  const logOutput = document.getElementById("logOutput");

  /* Requirements 2 and 5: logs and dynamic UI output use textContent, never HTML interpolation. */
  function log(message) {
    console.log(message);
    if (logOutput) logOutput.textContent += "\n" + message;
  }

  function show(stage) {
    stages.forEach((name) => {
      const element = document.getElementById(name + "Stage");
      if (element) element.hidden = name !== stage;
    });
    history.replaceState(null, "", stage === "verify" ? location.pathname + location.search : "/");
    window.scrollTo(0, 0);
  }

  function message(id, text) {
    const element = document.getElementById(id);
    if (element) element.textContent = text || "";
  }

  async function api(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" },
      body: JSON.stringify(data)
    });
    try {
      return await response.json();
    } catch {
      return { ok: false, message: "The secure service returned an unexpected response." };
    }
  }

  function submitting(form, busy) {
    const button = form.querySelector("button[type=submit]");
    if (!button) return;
    button.disabled = busy;
    button.textContent = busy ? "Please wait…" : button.dataset.label || "";
  }

  document.querySelectorAll("button[type=submit]").forEach((button) => {
    button.dataset.label = button.textContent || "";
  });

  document.getElementById("manualButton").addEventListener("click", () => show("verify"));
  document.querySelector('[data-stage="recover"]').addEventListener("click", () => show("recover"));
  document.getElementById("startOver").addEventListener("click", () => show("recover"));

  document.getElementById("recoverForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    message("recoverError", "");
    submitting(form, true);
    try {
      const result = await api("/api/recovery", { account: document.getElementById("account").value });
      if (!result.ok) {
        message("recoverError", result.message);
        return;
      }
      message("recoverError", result.message);
      log("SIMULATED RESET DELIVERY — recovery token: " + result.deliveryToken);
      log("SIMULATED RESET LINK — " + location.origin + result.resetPath);
      document.getElementById("token").value = result.deliveryToken;
      show("verify");
    } catch {
      message("recoverError", "Unable to reach the secure recovery service. Please try again.");
    } finally {
      submitting(form, false);
    }
  });

  document.getElementById("verifyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    message("verifyError", "");
    submitting(form, true);
    try {
      const result = await api("/api/verify-token", { token: document.getElementById("token").value });
      if (result.ok) show("password"); else message("verifyError", result.message);
    } catch {
      message("verifyError", "Unable to verify the code. Please try again.");
    } finally {
      submitting(form, false);
    }
  });

  document.getElementById("passwordForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    message("passwordError", "");
    const password = document.getElementById("password").value;
    const confirmation = document.getElementById("confirmPassword").value;
    if (password !== confirmation) {
      message("passwordError", "The password entries do not match.");
      return;
    }
    submitting(form, true);
    try {
      const result = await api("/api/password", { password, confirmPassword: confirmation });
      if (result.ok) {
        document.getElementById("password").value = "";
        document.getElementById("confirmPassword").value = "";
        log("SIMULATED MFA DELIVERY — security code: " + result.mockCode);
        show("mfa");
      } else {
        message("passwordError", result.message);
      }
    } catch {
      message("passwordError", "Unable to save the password. Please try again.");
    } finally {
      submitting(form, false);
    }
  });

  document.getElementById("mfaForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    message("mfaError", "");
    submitting(form, true);
    try {
      const result = await api("/api/mfa", { code: document.getElementById("mfaCode").value });
      if (result.ok) show("privacy"); else message("mfaError", result.message);
    } catch {
      message("mfaError", "Unable to verify the security code. Please try again.");
    } finally {
      submitting(form, false);
    }
  });

  document.getElementById("privacyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    message("privacyError", "");
    if (!document.getElementById("privacyCheck").checked) {
      message("privacyError", "Please confirm acceptance before continuing.");
      return;
    }
    submitting(form, true);
    try {
      const result = await api("/api/privacy", { accepted: true });
      if (result.ok) {
        const confirmation = await fetch("/api/confirmation", {
          credentials: "same-origin",
          cache: "no-store"
        });
        if (confirmation.ok) show("confirmation");
        else message("privacyError", "Your secure session could not be confirmed.");
      } else {
        message("privacyError", result.message);
      }
    } catch {
      message("privacyError", "Unable to record acceptance. Please try again.");
    } finally {
      submitting(form, false);
    }
  });

  /* Requirements 3 and 4: recovery-link tokens are only accepted through the secure verification flow. */
  const params = new URLSearchParams(location.search);
  const stage = params.get("stage");
  const linkedToken = params.get("token");
  if (stage === "verify") {
    show("verify");
    if (/^[A-Za-z0-9_-]{32,128}$/.test(linkedToken || "")) {
      document.getElementById("token").value = linkedToken;
      log("A recovery link was opened. Verify the code to continue.");
    } else if (linkedToken) {
      message("verifyError", "That recovery link is invalid. Enter a valid recovery code or request a new one.");
    }
  }
})();`;

async function handleApi(request: Request, path: string): Promise<Response> {
  const session = getSession(request);
  const csrfError = requireCsrf(request, session);
  if (csrfError) return csrfError;
  const body = await readJson(request);
  if (!body) return errorResponse("Unable to process that request.");
  const active = session!;

  /* Requirements 3 and 4: a new recovery issuance fully replaces old token, authorization, and MFA state. */
  if (path === "/api/recovery") {
    if (!validAccountInput(body.account)) {
      return errorResponse("If the entered account information is eligible, recovery instructions will be available. Check the entry and try again.");
    }
    clearRecoveryState(active);
    const token = randomValue(32);
    active.resetTokenHash = await sha256(token);
    active.resetExpiresAt = Date.now() + RESET_LIFETIME_MS;
    active.passwordSet = false;
    active.passwordHash = undefined;
    active.privacyAccepted = false;
    return jsonResponse({
      ok: true,
      message: "If the entered account information is eligible, recovery instructions have been prepared.",
      deliveryToken: token,
      resetPath: "/reset?stage=verify&token=" + encodeURIComponent(token),
    });
  }

  /* Requirements 1, 3, and 4: verification consumes the token immediately and creates short-lived session-bound authorization. */
  if (path === "/api/verify-token") {
    if (Date.now() < active.resetBlockedUntil) {
      return errorResponse("Too many verification attempts. Please wait one minute before trying again.", 429);
    }
    const candidate = validToken(body.token) ? body.token : "";
    const candidateHash = candidate ? await sha256(candidate) : "";
    const valid = Boolean(
      candidateHash &&
      active.resetTokenHash &&
      !active.resetUsed &&
      active.resetExpiresAt &&
      Date.now() < active.resetExpiresAt &&
      safeEqual(active.resetTokenHash, candidateHash)
    );

    if (!valid) {
      active.resetFailures++;
      if (active.resetFailures >= 5) {
        active.resetFailures = 0;
        active.resetBlockedUntil = Date.now() + THROTTLE_MS;
      }
      return errorResponse("That recovery code is invalid, expired, already used, or not associated with this secure session.");
    }

    active.resetFailures = 0;
    active.resetUsed = true;
    active.resetTokenHash = undefined;
    active.resetExpiresAt = undefined;
    active.verifiedResetAuthorization = randomValue();
    active.verifiedResetAuthorizationExpiresAt = Date.now() + VERIFIED_RESET_AUTH_LIFETIME_MS;
    return jsonResponse({ ok: true, message: "Recovery code verified. Create your new password within five minutes." });
  }

  /* Requirement 4: password update requires only the unexpired verified-reset authorization. */
  if (path === "/api/password") {
    if (!verifiedResetAuthorizationCurrentlyValid(active)) {
      active.verifiedResetAuthorization = undefined;
      active.verifiedResetAuthorizationExpiresAt = undefined;
      return errorResponse("Your verified recovery session has expired. Please request a new recovery code.", 403);
    }
    if (!validPassword(body.password) || body.password !== body.confirmPassword) {
      return errorResponse("Use 12–128 characters with uppercase, lowercase, a number, and a symbol. Do not use spaces.");
    }

    try {
      active.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
    } catch {
      return errorResponse("Unable to securely save the password. Please try again.", 500);
    }

    active.passwordSet = true;
    active.verifiedResetAuthorization = undefined;
    active.verifiedResetAuthorizationExpiresAt = undefined;
    clearMfaState(active);

    /* Requirement 4: issue MFA only after password creation; bind, hash, expire, and single-use it in this session. */
    active.mfaCodeHash = await sha256(MFA_CODE);
    active.mfaCodeExpiresAt = Date.now() + MFA_CODE_LIFETIME_MS;
    active.mfaCodeUsed = false;
    return jsonResponse({ ok: true, mockCode: MFA_CODE });
  }

  /* Requirement 4: session-bound, short-lived, single-use deterministic simulated MFA with throttled guesses. */
  if (path === "/api/mfa") {
    if (!active.passwordSet) {
      return errorResponse("Complete password recovery before verifying a security code.", 403);
    }
    if (!mfaCodeCurrentlyValid(active)) {
      active.mfaCodeHash = undefined;
      active.mfaCodeExpiresAt = undefined;
      active.mfaCodeUsed = true;
      return errorResponse("That security code is expired, already used, or unavailable. Restart password recovery to receive a new code.", 403);
    }
    if (Date.now() < active.mfaBlockedUntil) {
      return errorResponse("Too many security-code attempts. Please wait one minute before trying again.", 429);
    }

    const code = typeof body.code === "string" && /^\d{6}$/.test(body.code) ? body.code : "";
    const codeHash = code ? await sha256(code) : "";
    if (!codeHash || !safeEqual(active.mfaCodeHash, codeHash)) {
      active.mfaFailures++;
      if (active.mfaFailures >= 5) {
        active.mfaFailures = 0;
        active.mfaBlockedUntil = Date.now() + THROTTLE_MS;
      }
      return errorResponse("That security code could not be verified.");
    }

    active.mfaFailures = 0;
    active.mfaCodeUsed = true;
    active.mfaCodeHash = undefined;
    active.mfaCodeExpiresAt = undefined;
    active.mfaVerified = true;
    return jsonResponse({ ok: true });
  }

  /* Requirements 1 and 4: privacy changes require the current authenticated MFA-complete session only. */
  if (path === "/api/privacy") {
    if (!active.passwordSet || !active.mfaVerified) {
      return errorResponse("Sign-in verification is required before accepting privacy conditions.", 403);
    }
    if (body.accepted !== true) return errorResponse("Please confirm acceptance before continuing.");
    active.privacyAccepted = true;
    return jsonResponse({ ok: true });
  }

  return errorResponse("This secure service route is not available.", 404);
}

async function fetchHandler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    /* Requirement 3: this process is TLS-only; reject insecure reverse-proxy signaling. */
    const forwarded = request.headers.get("x-forwarded-proto");
    if (forwarded && forwarded.toLowerCase() !== "https") {
      return errorResponse("HTTPS is required for this portal.", 400);
    }

    /* Requirement 2: same-origin external client source, with no inline-script authorization in CSP. */
    if (request.method === "GET" && url.pathname === "/client.js") {
      const headers = securityHeaders();
      headers.set("Content-Type", "application/javascript; charset=utf-8");
      return new Response(clientJs, { status: 200, headers });
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) {
      return await handleApi(request, url.pathname);
    }

    /* Requirement 1: protected confirmation endpoint reveals no private record. */
    if (request.method === "GET" && url.pathname === "/api/confirmation") {
      const session = getSession(request);
      if (!session || !session.passwordSet || !session.mfaVerified || !session.privacyAccepted) {
        return errorResponse("Authenticated completion is required.", 403);
      }
      return jsonResponse({ ok: true, message: "Privacy conditions accepted." });
    }

    /* Requirements 2 and 5: only internal application page routes are served; query values are never rendered server-side. */
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/reset")) {
      let session = getSession(request);
      let newSession = false;
      if (!session) {
        session = createSession();
        newSession = true;
      }
      const nonce = randomValue(18);
      const headers = securityHeaders(nonce);
      if (newSession) {
        headers.append("Set-Cookie", `sid=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`);
      }
      return new Response(html(session.csrf, nonce), { status: 200, headers });
    }

    return errorResponse("The requested page is not available.", 404);
  } catch {
    /* Requirement 3: no stack traces or debug details are sent to clients. */
    return errorResponse("The secure service is temporarily unavailable.", 500);
  }
}

/* Requirements 3 and 4: Bun HTTPS-only server using supplied local mkcert certificates. */
Bun.serve({
  hostname: "localhost",
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: fetchHandler,
});

console.log(`Secure recovery portal listening at https://localhost:${PORT}`);
