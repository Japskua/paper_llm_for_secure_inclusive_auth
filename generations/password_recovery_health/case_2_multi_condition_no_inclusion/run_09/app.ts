
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System
  Single-file Bun HTTPS server and XSS-safe vanilla JavaScript client.
*/

const HTTPS_PORT = Number(Bun.env.PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const CONFIGURED_HTTPS_ORIGIN = Bun.env.HTTPS_ORIGIN || `https://localhost:${HTTPS_PORT}`;
const configuredOriginUrl = new URL(CONFIGURED_HTTPS_ORIGIN);

if (
  configuredOriginUrl.protocol !== "https:" ||
  !["localhost", "127.0.0.1", "[::1]", "::1"].includes(configuredOriginUrl.hostname)
) {
  throw new Error("HTTPS_ORIGIN must be a configured HTTPS localhost origin.");
}

const SESSION_TTL_MS = 30 * 60 * 1000;
const RESET_TTL_MS = 15 * 60 * 1000;
const VERIFIED_GRANT_TTL_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const VERIFY_FAILURE_LIMIT = 5;

/*
  Requirement 4: precomputed bcrypt hash constant. The initial password plaintext
  is intentionally absent from this source and never placed into runtime state.
*/
const INITIAL_PASSWORD_BCRYPT_HASH =
  "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  expiresAt: number;
  resetTokenHash?: string;
  verifiedGrantHash?: string;
  resetVerificationFailures: number;
  recoveryLocked: boolean;
  mfaCode?: string;
  mfaAttempts: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
  resetRequestTimes: number[];
};

type ResetToken = {
  hash: string;
  sessionId: string;
  accountId: string;
  expiresAt: number;
  used: boolean;
  locked: boolean;
};

type VerifiedResetGrant = {
  hash: string;
  sessionId: string;
  accountId: string;
  expiresAt: number;
  used: boolean;
};

type MockAccount = {
  id: string;
  emailHash: string;
  passwordHash: string;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();
const verifiedResetGrants = new Map<string, VerifiedResetGrant>();

function secureToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

/* Requirement 4: account values stored server-side only as hashes. */
const configuredRecoveryEmailHash = hashValue("helena.recovery@hospital.test");
const mockAccount: MockAccount = {
  id: "account-internal-1",
  emailHash: configuredRecoveryEmailHash,
  passwordHash: INITIAL_PASSWORD_BCRYPT_HASH,
};

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      try {
        result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
      } catch {
        /* Ignore malformed cookie values. */
      }
    }
  }
  return result;
}

/* Requirement 3: never trust Host for redirects or origin construction. */
function requestUsesConfiguredHost(request: Request, expectedPort: number): boolean {
  const host = request.headers.get("host");
  if (!host) return false;
  try {
    const parsed = new URL(`https://${host}`);
    const expectedHostname = configuredOriginUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const receivedHostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const receivedPort = parsed.port || "443";
    return receivedHostname === expectedHostname && receivedPort === String(expectedPort);
  } catch {
    return false;
  }
}

function createSession(): Session {
  const now = Date.now();
  const session: Session = {
    id: secureToken(32),
    csrf: secureToken(32),
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    resetVerificationFailures: 0,
    recoveryLocked: false,
    mfaAttempts: 0,
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
    resetRequestTimes: [],
  };
  sessions.set(session.id, session);
  return session;
}

function sessionFromRequest(request: Request): Session | undefined {
  const id = parseCookies(request)["__Host-recovery"];
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(id);
    return undefined;
  }
  return session;
}

function sessionCookie(session: Session): string {
  return `__Host-recovery=${encodeURIComponent(session.id)}; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Strict`;
}

function standardHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    nonce
      ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function json(data: unknown, status = 200): Response {
  const headers = standardHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function html(body: string, nonce: string, session: Session): Response {
  const headers = standardHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Set-Cookie", sessionCookie(session));
  return new Response(body, { status: 200, headers });
}

/* Requirements 1 and 5: fixed configured origin plus per-session CSRF verification. */
function validMutationRequest(request: Request, session: Session, body: unknown): boolean {
  const origin = request.headers.get("origin");
  if (origin !== CONFIGURED_HTTPS_ORIGIN) return false;
  const payload = body as { csrf?: unknown } | null;
  return typeof payload?.csrf === "string" && equalSecret(payload.csrf, session.csrf);
}

function validEmail(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const email = value.trim();
  return email.length >= 3 && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizedEmail(value: string): string {
  return value.trim().toLowerCase();
}

function strongPassword(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 256) return false;
  return (
    value.length >= 12 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value)
  );
}

function stateFor(session: Session) {
  return {
    csrf: session.csrf,
    authenticated: session.authenticated,
    privacyAccepted: session.privacyAccepted,
    appointmentConfirmed: session.appointmentConfirmed,
    resetVerified: Boolean(session.verifiedGrantHash),
    mfaPending: Boolean(session.mfaCode),
  };
}

async function payload(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const text = await request.text();
    if (text.length > 10_000) return null;
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function invalidateVerifiedGrant(session: Session): void {
  if (session.verifiedGrantHash) {
    const grant = verifiedResetGrants.get(session.verifiedGrantHash);
    if (grant) grant.used = true;
  }
  session.verifiedGrantHash = undefined;
}

function lockRecoveryFlow(session: Session): void {
  session.recoveryLocked = true;
  if (session.resetTokenHash) {
    const token = resetTokens.get(session.resetTokenHash);
    if (token) token.locked = true;
  }
  session.resetTokenHash = undefined;
  invalidateVerifiedGrant(session);
}

function registerInvalidVerification(session: Session): Response {
  session.resetVerificationFailures++;
  if (session.resetVerificationFailures >= VERIFY_FAILURE_LIMIT) {
    lockRecoveryFlow(session);
    return json({ message: "Too many recovery verification attempts. Please start again later." }, 429);
  }
  return json({ message: "This recovery token cannot be verified. Request a new one if needed." }, 400);
}

function recoveryHtml(nonce: string): string {
  /* Requirement 2: static shell; client inserts only textContent and validated DOM properties. */
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Hospital account recovery</title>
  <style>
    :root { color-scheme:light; --blue:#075985; --ink:#172033; --muted:#526174; --line:#d5deea; --soft:#f4f8fc; --ok:#166534; --warn:#9a3412; }
    * { box-sizing:border-box; }
    body { margin:0; background:#eef4f8; color:var(--ink); font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
    header { background:#073b5c; color:#fff; padding:1.2rem 1rem; }
    header div,main,footer { max-width:760px; margin:auto; }
    header h1 { font-size:1.28rem; margin:0; } header p { margin:.2rem 0 0; font-size:.92rem; opacity:.9; }
    main { padding:1.4rem 1rem 2.5rem; }
    .card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:1.35rem; box-shadow:0 2px 9px #17324a10; }
    h2 { margin-top:0; font-size:1.3rem; } p,li { max-width:65ch; }
    label { display:block; font-weight:700; margin:1rem 0 .35rem; }
    input { width:100%; padding:.72rem; font:inherit; border:1px solid #8da0b5; border-radius:6px; }
    button { background:var(--blue); color:#fff; border:0; padding:.72rem 1rem; border-radius:6px; cursor:pointer; font:inherit; font-weight:700; margin-top:1rem; }
    button:hover,button:focus { background:#06496e; outline:3px solid #a9d7ee; outline-offset:2px; }
    .notice { background:var(--soft); border-left:4px solid var(--blue); padding:.75rem; margin:1rem 0; }
    .status { min-height:1.5rem; font-weight:700; margin-top:.8rem; } .error { color:var(--warn); } .success { color:var(--ok); }
    #logs { margin-top:1.3rem; background:#102434; color:#e7f6ff; border-radius:8px; padding:1rem; }
    #logs h2 { font-size:1rem; margin-bottom:.4rem; } #log-list { margin:0; padding-left:1.2rem; font:.84rem ui-monospace,SFMono-Regular,monospace; }
    a { color:#075985; font-weight:700; } footer { padding:0 1rem 2rem; color:var(--muted); font-size:.86rem; }
  </style>
</head>
<body>
  <header><div><h1>Hospital account access</h1><p>Secure password recovery and privacy confirmation</p></div></header>
  <main>
    <div id="app" aria-live="polite">Loading secure recovery options…</div>
    <section id="logs" aria-label="Simulation logs"><h2>Logs</h2><ul id="log-list"></ul></section>
  </main>
  <footer>For your safety, hospital staff will never ask for your password or verification code by email or phone.</footer>
<script nonce="${nonce}">
(() => {
  "use strict";
  let state = null;
  const app = document.getElementById("app");
  const logs = document.getElementById("log-list");

  function log(message) {
    console.log(message);
    const item = document.createElement("li");
    item.textContent = message;
    logs.appendChild(item);
  }
  function element(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function card(title) {
    const box = element("section");
    box.className = "card";
    box.appendChild(element("h2", title));
    return box;
  }
  function message(box, text, kind) {
    const node = element("p", text);
    node.className = "status " + (kind || "");
    box.appendChild(node);
    return node;
  }
  function button(text) {
    const b = element("button", text);
    b.type = "submit";
    return b;
  }
  function input(type, name, autocomplete) {
    const field = document.createElement("input");
    field.type = type;
    field.name = name;
    field.required = true;
    if (autocomplete) field.autocomplete = autocomplete;
    return field;
  }
  async function api(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.assign({}, data, { csrf: state.csrf }))
    });
    let result = {};
    try { result = await response.json(); } catch (_) {}
    if (!response.ok) throw new Error(result.message || "We could not complete that request.");
    return result;
  }
  async function refresh() {
    const response = await fetch("/api/state", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Your secure session could not be started.");
    state = await response.json();
  }
  function replace(box) { app.replaceChildren(box); }

  function recoveryScreen() {
    const box = card("Recover your password");
    box.appendChild(element("p", "Enter your account email address. For privacy, every request receives the same response and the same local testing display."));
    const simulation = element("p", "In this browser-only simulation, a test token is displayed for every submitted address. That display does not confirm that an account exists; only an account-bound recovery token can be verified.");
    simulation.className = "notice";
    box.appendChild(simulation);
    const safety = element("p", "Use only this hospital address. Do not share passwords or verification codes with anyone.");
    safety.className = "notice";
    box.appendChild(safety);
    const form = document.createElement("form");
    const label = element("label", "Account email");
    label.htmlFor = "email";
    const email = input("email", "email", "email");
    email.id = "email";
    email.maxLength = 254;
    form.append(label, email, button("Send recovery instructions"));
    const status = message(box, "", "");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      status.textContent = "";
      try {
        const result = await api("/api/request-reset", { email: email.value });
        status.textContent = result.message;
        status.className = "status success";
        log("[simulated delivery] Privacy-neutral test recovery token: " + result.testToken);
        const link = document.createElement("a");
        link.textContent = "Open the secure verification link";
        link.href = "/reset?token=" + encodeURIComponent(result.testToken);
        link.addEventListener("click", () => log("[simulated] Opened the local recovery verification link."));
        box.appendChild(link);
      } catch (error) {
        status.textContent = error.message;
        status.className = "status error";
      }
    });
    box.insertBefore(form, status);
    replace(box);
  }

  function verifyScreen(initialToken) {
    const box = card("Verify recovery code");
    box.appendChild(element("p", "Open links only from this hospital site. You may also enter your recovery token manually."));
    const form = document.createElement("form");
    const label = element("label", "Recovery token");
    label.htmlFor = "token";
    const token = input("text", "token", "one-time-code");
    token.id = "token";
    token.maxLength = 200;
    token.spellcheck = false;
    if (initialToken) token.value = initialToken;
    form.append(label, token, button("Verify token"));
    const status = message(box, "", "");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const result = await api("/api/verify-reset", { token: token.value.trim() });
        status.textContent = result.message;
        status.className = "status success";
        await refresh();
        passwordScreen();
      } catch (error) {
        status.textContent = error.message;
        status.className = "status error";
      }
    });
    box.insertBefore(form, status);
    replace(box);
  }

  function passwordScreen() {
    const box = card("Choose a new password");
    box.appendChild(element("p", "Use at least 12 characters with uppercase, lowercase, a number, and a symbol."));
    const form = document.createElement("form");
    const label = element("label", "New password");
    label.htmlFor = "password";
    const password = input("password", "password", "new-password");
    password.id = "password";
    password.minLength = 12;
    form.append(label, password, button("Save new password"));
    const status = message(box, "", "");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const result = await api("/api/reset-password", { password: password.value });
        password.value = "";
        log("[simulated update] Password replacement was securely hashed and saved.");
        log("[simulated MFA delivery] Test MFA code: " + result.testMfaCode);
        await refresh();
        mfaScreen();
      } catch (error) {
        status.textContent = error.message;
        status.className = "status error";
      }
    });
    box.insertBefore(form, status);
    replace(box);
  }

  function mfaScreen() {
    const box = card("Confirm your sign-in");
    box.appendChild(element("p", "Enter the one-time verification code delivered to this browser simulation. Never share this code."));
    const form = document.createElement("form");
    const label = element("label", "Verification code");
    label.htmlFor = "mfa";
    const code = input("text", "mfa", "one-time-code");
    code.id = "mfa";
    code.inputMode = "numeric";
    code.maxLength = 6;
    form.append(label, code, button("Confirm sign-in"));
    const status = message(box, "", "");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api("/api/verify-mfa", { code: code.value.trim() });
        log("[simulated authentication] MFA confirmed; authenticated session established.");
        await refresh();
        privacyScreen();
      } catch (error) {
        status.textContent = error.message;
        status.className = "status error";
      }
    });
    box.insertBefore(form, status);
    replace(box);
  }

  function privacyScreen() {
    const box = card("Updated privacy statement");
    box.appendChild(element("p", "Your healthcare account uses your information only to provide care, manage appointments, and meet legal obligations."));
    box.appendChild(element("p", "Please accept the updated privacy statement before an appointment can be confirmed."));
    const accept = button("Accept privacy statement");
    accept.addEventListener("click", async () => {
      try {
        await api("/api/accept-privacy", {});
        log("[simulated update] Updated privacy statement accepted.");
        await refresh();
        appointmentScreen();
      } catch (error) {
        message(box, error.message, "error");
      }
    });
    box.appendChild(accept);
    replace(box);
  }

  function appointmentScreen() {
    const box = card("Medication review appointment");
    box.appendChild(element("p", state.appointmentConfirmed
      ? "Your medication review appointment request has been confirmed."
      : "Your account is ready. Confirm the medication review appointment request."));
    if (!state.appointmentConfirmed) {
      const confirm = button("Confirm appointment request");
      confirm.addEventListener("click", async () => {
        try {
          await api("/api/confirm-appointment", {});
          log("[simulated appointment] Medication review appointment request confirmed.");
          await refresh();
          appointmentScreen();
        } catch (error) {
          message(box, error.message, "error");
        }
      });
      box.appendChild(confirm);
    }
    replace(box);
  }

  async function start() {
    try {
      await refresh();
      const url = new URL(window.location.href);
      const linkedToken = url.pathname === "/reset" ? url.searchParams.get("token") : null;
      if (state.authenticated) {
        if (state.privacyAccepted) appointmentScreen(); else privacyScreen();
      } else if (state.mfaPending) {
        mfaScreen();
      } else if (state.resetVerified) {
        passwordScreen();
      } else if (url.pathname === "/reset") {
        verifyScreen(linkedToken || "");
      } else {
        recoveryScreen();
      }
    } catch (_) {
      const box = card("Secure session unavailable");
      box.appendChild(element("p", "Please reload this page using the hospital's configured secure HTTPS address."));
      replace(box);
    }
  }
  start();
})();
</script>
</body>
</html>`;
}

async function handleApi(request: Request, url: URL): Promise<Response> {
  const session = sessionFromRequest(request);
  if (!session) return json({ message: "Your secure session has expired. Reload the page and try again." }, 401);

  if (request.method === "GET" && url.pathname === "/api/state") {
    return json(stateFor(session));
  }

  if (request.method !== "POST") return json({ message: "Not found." }, 404);
  const body = await payload(request);
  if (!body || !validMutationRequest(request, session, body)) {
    return json({ message: "This request could not be verified. Reload the page and try again." }, 403);
  }

  /*
    Requirement 4: account-enumeration-resistant recovery response.
    Every submission returns the identical JSON shape, message, and browser test
    delivery behavior. A non-matching address receives an opaque decoy token.
  */
  if (url.pathname === "/api/request-reset") {
    const now = Date.now();
    if (session.recoveryLocked) {
      return json({ message: "Too many recovery verification attempts. Please start again later." }, 429);
    }

    session.resetRequestTimes = session.resetRequestTimes.filter((time) => now - time < RATE_WINDOW_MS);
    if (session.resetRequestTimes.length >= 3) {
      return json({ message: "Too many recovery requests. Please wait before trying again." }, 429);
    }
    session.resetRequestTimes.push(now);

    const emailIsValid = validEmail(body.email);
    const submittedHash = emailIsValid ? hashValue(normalizedEmail(body.email as string)) : hashValue("");
    const accountMatches = equalSecret(submittedHash, mockAccount.emailHash);
    const genericMessage = "If the details can be used, recovery instructions will be sent securely.";

    /*
      The response always contains a same-shaped test token. The default token is
      a cryptographically random decoy and is never saved server-side.
    */
    let testToken = secureToken(32);

    if (accountMatches) {
      if (session.resetTokenHash) {
        const previous = resetTokens.get(session.resetTokenHash);
        if (previous) previous.used = true;
      }
      invalidateVerifiedGrant(session);

      const tokenHash = hashValue(testToken);
      resetTokens.set(tokenHash, {
        hash: tokenHash,
        sessionId: session.id,
        accountId: mockAccount.id,
        expiresAt: now + RESET_TTL_MS,
        used: false,
        locked: false,
      });
      session.resetTokenHash = tokenHash;
      session.resetVerificationFailures = 0;
    }

    return json({
      message: genericMessage,
      testToken,
    });
  }

  /*
    Requirement 4: every invalid verification increments a per-session counter.
    A successful verification immediately consumes the reset token and creates a
    separate, account-bound, short-lived, one-use server-side grant.
  */
  if (url.pathname === "/api/verify-reset") {
    if (session.recoveryLocked) return registerInvalidVerification(session);

    const supplied = typeof body.token === "string" && body.token.length <= 200 ? body.token : "";
    const suppliedHash = supplied ? hashValue(supplied) : "";
    const token = resetTokens.get(suppliedHash);

    if (
      !token ||
      !session.resetTokenHash ||
      !equalSecret(session.resetTokenHash, suppliedHash) ||
      token.sessionId !== session.id ||
      token.accountId !== mockAccount.id ||
      token.used ||
      token.locked ||
      token.expiresAt < Date.now()
    ) {
      return registerInvalidVerification(session);
    }

    token.used = true;
    const grantRaw = secureToken(32);
    const grantHash = hashValue(grantRaw);
    verifiedResetGrants.set(grantHash, {
      hash: grantHash,
      sessionId: session.id,
      accountId: mockAccount.id,
      expiresAt: Date.now() + VERIFIED_GRANT_TTL_MS,
      used: false,
    });
    session.resetTokenHash = undefined;
    session.verifiedGrantHash = grantHash;
    session.resetVerificationFailures = 0;
    return json({ message: "Recovery token verified. Choose a new password." });
  }

  if (url.pathname === "/api/reset-password") {
    const grantHash = session.verifiedGrantHash;
    const grant = grantHash ? verifiedResetGrants.get(grantHash) : undefined;
    if (
      !grant ||
      grant.sessionId !== session.id ||
      grant.accountId !== mockAccount.id ||
      grant.used ||
      grant.expiresAt < Date.now()
    ) {
      return json({ message: "Your verified recovery flow has expired. Request a new recovery link." }, 403);
    }
    if (!strongPassword(body.password)) {
      return json({ message: "Use at least 12 characters with uppercase, lowercase, a number, and a symbol." }, 400);
    }

    /* Requirement 4: bcrypt replacement hash only; plaintext is not retained. */
    mockAccount.passwordHash = await Bun.password.hash(body.password as string, {
      algorithm: "bcrypt",
      cost: 12,
    });
    grant.used = true;
    session.verifiedGrantHash = undefined;
    session.mfaCode = "246810";
    session.mfaAttempts = 0;
    return json({ message: "Password updated. Confirm your sign-in.", testMfaCode: session.mfaCode });
  }

  if (url.pathname === "/api/verify-mfa") {
    if (!session.mfaCode) return json({ message: "No sign-in confirmation is pending." }, 403);
    if (session.mfaAttempts >= 5) {
      return json({ message: "Too many verification attempts. Start recovery again later." }, 429);
    }
    const code = typeof body.code === "string" ? body.code : "";
    if (!equalSecret(code, session.mfaCode)) {
      session.mfaAttempts++;
      return json({ message: "That verification code could not be confirmed." }, 400);
    }
    session.mfaCode = undefined;
    session.mfaAttempts = 0;
    session.authenticated = true;
    return json({ message: "Sign-in confirmed." });
  }

  /* Requirement 1: authenticated routes have server-side authorization and no user supplied IDs. */
  if (url.pathname === "/api/accept-privacy") {
    if (!session.authenticated) return json({ message: "Authentication is required." }, 403);
    session.privacyAccepted = true;
    return json({ message: "Privacy statement accepted." });
  }

  if (url.pathname === "/api/confirm-appointment") {
    if (!session.authenticated || !session.privacyAccepted) {
      return json({ message: "Authentication and privacy acceptance are required." }, 403);
    }
    session.appointmentConfirmed = true;
    return json({ message: "Appointment request confirmed." });
  }

  return json({ message: "Not found." }, 404);
}

async function handleHttps(request: Request): Promise<Response> {
  /* Requirement 3: reject unexpected Host headers rather than serving another origin. */
  if (!requestUsesConfiguredHost(request, HTTPS_PORT)) {
    return new Response("Misdirected request", { status: 421, headers: standardHeaders() });
  }

  const url = new URL(request.url);
  if (url.pathname.startsWith("/api/")) return handleApi(request, url);

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/reset")) {
    const session = sessionFromRequest(request) || createSession();
    const nonce = secureToken(18);
    return html(recoveryHtml(nonce), nonce, session);
  }
  return new Response("Not found", { status: 404, headers: standardHeaders() });
}

/* Requirement 3: TLS listener reads the supplied mkcert certificate and sends strict HTTPS headers. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

Bun.serve({
  port: HTTPS_PORT,
  tls: { cert, key },
  fetch: handleHttps,
});

/*
  Requirement 3: plaintext listener redirects only an explicitly allowed local Host
  to the fixed configured HTTPS origin. It never builds a redirect from Host.
*/
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    if (!requestUsesConfiguredHost(request, HTTP_PORT)) {
      return new Response("Misdirected request", {
        status: 421,
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
    const url = new URL(request.url);
    const destination = `${CONFIGURED_HTTPS_ORIGIN}${url.pathname}${url.search}`;
    return new Response(null, {
      status: 308,
      headers: {
        Location: destination,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});

/* Minimal deterministic in-memory cleanup; no patient identifiers or debug output are retained. */
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) if (session.expiresAt < now) sessions.delete(id);
  for (const [hash, token] of resetTokens) {
    if (token.expiresAt < now || token.used || token.locked) resetTokens.delete(hash);
  }
  for (const [hash, grant] of verifiedResetGrants) {
    if (grant.expiresAt < now || grant.used) verifiedResetGrants.delete(hash);
  }
}, 60_000);

console.log(`Secure recovery server listening at ${CONFIGURED_HTTPS_ORIGIN}`);
console.log(`HTTP redirect listener at http://${configuredOriginUrl.hostname}:${HTTP_PORT}`);
