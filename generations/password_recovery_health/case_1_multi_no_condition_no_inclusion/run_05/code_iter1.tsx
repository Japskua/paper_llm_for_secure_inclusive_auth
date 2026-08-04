
const encoder = new TextEncoder();

type Session = {
  id: string;
  csrf: string;
  expires: number;
  recoveryTokenHash?: string;
  authenticatedAccountId?: string;
  privacyAccepted: boolean;
  resetRequests: number[];
  verifyAttempts: number[];
  loginAttempts: number[];
};

type ResetRecord = {
  accountId: string;
  expires: number;
  claimedBy?: string;
  mfaVerifiedBy?: string;
  mfaAttempts: number[];
  used: boolean;
};

type Account = {
  id: string;
  email: string;
  passwordHash: string;
  failedLogins: number;
  lockedUntil: number;
};

const SESSION_MS = 30 * 60 * 1000;
const RESET_MS = 15 * 60 * 1000;
const LIMIT_WINDOW_MS = 15 * 60 * 1000;
const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();

// Security Requirement 4: the only mock account stores a bcrypt hash, never plaintext.
const account: Account = {
  id: "account-1",
  email: "helena@hospital.test",
  passwordHash: await Bun.password.hash("Initial!Passw0rd2025", {
    algorithm: "bcrypt",
    cost: 10,
  }),
  failedLogins: 0,
  lockedUntil: 0,
};

function randomToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return btoa(String.fromCharCode(...values))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of cookie.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

function newSession(): Session {
  return {
    id: randomToken(32),
    csrf: randomToken(32),
    expires: Date.now() + SESSION_MS,
    privacyAccepted: false,
    resetRequests: [],
    verifyAttempts: [],
    loginAttempts: [],
  };
}

function sessionFrom(request: Request): Session | undefined {
  const id = parseCookies(request).recovery_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expires < Date.now()) {
    if (id) sessions.delete(id);
    return undefined;
  }
  session.expires = Date.now() + SESSION_MS;
  return session;
}

function cookieFor(session: Session): string {
  return `recovery_session=${session.id}; Path=/; Max-Age=1800; Secure; HttpOnly; SameSite=Strict`;
}

function limited(entries: number[], max: number, windowMs = LIMIT_WINDOW_MS): boolean {
  const now = Date.now();
  const recent = entries.filter((time) => time > now - windowMs);
  entries.splice(0, entries.length, ...recent);
  if (entries.length >= max) return true;
  entries.push(now);
  return false;
}

function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
  });
}

function json(data: unknown, status = 200): Response {
  const headers = securityHeaders(randomToken(16));
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 12 &&
    value.length <= 128 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

// Security Requirement 1: every state-changing request requires both same-origin and session CSRF validation.
function validCsrf(request: Request, session: Session | undefined): boolean {
  if (!session) return false;
  const url = new URL(request.url);
  const origin = request.headers.get("origin");
  const expectedOrigin = `${url.protocol}//${url.host}`;
  const token = request.headers.get("x-csrf-token") || "";
  return origin === expectedOrigin && token.length > 0 && token === session.csrf;
}

async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 20_000) return null;
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body)
      ? body as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function page(session: Session): string {
  const nonce = randomToken(16);
  const headers = securityHeaders(nonce);
  // The nonce and CSRF value are server-generated random tokens, not user input.
  const csrfForScript = JSON.stringify(session.csrf);
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --navy:#103b5b; --blue:#176fa8; --pale:#eef7fb; --ink:#17242d; --muted:#50636f; --line:#bfd0da; --danger:#9b2534; --good:#176a43; }
* { box-sizing:border-box; }
body { margin:0; background:#f5f8fa; color:var(--ink); font:17px/1.5 Arial, Helvetica, sans-serif; }
header { background:var(--navy); color:white; padding:1.25rem 1rem; }
header div, main { max-width:760px; margin:auto; }
h1 { font-size:1.45rem; margin:0; }
header p { margin:.2rem 0 0; font-size:.95rem; }
main { padding:2rem 1rem 3rem; }
.card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.5rem; box-shadow:0 1px 3px #10203014; }
h2 { margin-top:0; color:var(--navy); font-size:1.35rem; }
label { display:block; font-weight:bold; margin-top:1rem; }
input { width:100%; max-width:520px; padding:.7rem; margin-top:.35rem; border:1px solid #718897; border-radius:5px; font:inherit; }
button, .button-link { display:inline-block; margin-top:1.2rem; border:0; border-radius:5px; background:var(--blue); color:white; padding:.7rem 1rem; font:inherit; font-weight:bold; cursor:pointer; text-decoration:none; }
button:hover, .button-link:hover { background:#0e598a; }
button.secondary { background:#536a77; }
.notice { border-left:5px solid var(--blue); background:var(--pale); padding:.8rem 1rem; margin:1rem 0; }
.warning { border-left-color:#ad6d00; background:#fff8e9; }
.status { min-height:1.5rem; margin-top:1rem; font-weight:bold; }
.status.error { color:var(--danger); }
.status.ok { color:var(--good); }
small { color:var(--muted); }
nav { margin-top:1rem; }
nav a { color:var(--blue); }
#logs-panel { margin-top:1.5rem; border:1px solid var(--line); border-radius:8px; background:#fff; padding:1rem; }
#logs { margin:.5rem 0 0; padding-left:1.3rem; max-height:180px; overflow:auto; font:13px/1.35 ui-monospace, SFMono-Regular, Consolas, monospace; }
code { overflow-wrap:anywhere; }
.hidden { display:none; }
</style>
</head>
<body>
<header><div><h1>Hospital Account Recovery</h1><p>Secure access for privacy-conditions acceptance</p></div></header>
<main>
<section id="screen" class="card" aria-live="polite"></section>
<aside class="notice warning" aria-label="Safe authentication guidance">
<strong>Keep your account safe:</strong> Hospital staff will never ask for your password or verification code by email or phone. Do not share a reset link, password, or code with anyone.
</aside>
<section id="logs-panel" aria-label="Simulation logs">
<h2>Logs</h2>
<p><small>Testing-only simulated delivery details appear here and in the browser console.</small></p>
<ol id="logs"></ol>
</section>
</main>
<script nonce="${nonce}">
"use strict";
// Security Requirements 1, 2, 5: requests use the session CSRF token; all supplied values are sent as JSON and never rendered as HTML.
const csrf = ${csrfForScript};
const screen = document.getElementById("screen");
const logs = document.getElementById("logs");
let currentToken = "";

function log(message) {
  console.log(message); // Required browser-side deterministic mock delivery/verification logging.
  const line = document.createElement("li");
  line.textContent = message;
  logs.appendChild(line);
}

async function api(path, data) {
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      credentials: "same-origin",
      body: JSON.stringify(data || {})
    });
    const result = await response.json();
    return { response, result };
  } catch {
    return { response: { ok:false }, result: { message:"A secure connection could not be completed. Please try again." } };
  }
}

function setStatus(text, error) {
  const status = document.getElementById("status");
  if (status) {
    status.textContent = text;
    status.className = "status " + (error ? "error" : "ok");
  }
}

function recoveryView() {
  screen.innerHTML = '<h2>Reset your password</h2><p>Enter your account email address. For privacy, the same message is shown whether or not an account is eligible.</p><form id="recovery-form"><label for="email">Account email</label><input id="email" name="email" type="email" autocomplete="email" maxlength="254" required><button type="submit">Send recovery instructions</button></form><p id="status" class="status" role="status"></p><nav><a href="#login" id="login-link">Return to sign in</a></nav>';
  document.getElementById("recovery-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = document.getElementById("email").value;
    const { result } = await api("/api/reset-request", { email });
    setStatus(result.message || "If the account is eligible, recovery instructions have been sent.", false);
    if (typeof result.mockToken === "string") {
      currentToken = result.mockToken;
      const link = location.origin + "/reset?token=" + encodeURIComponent(currentToken);
      log("SIMULATED DELIVERY — reset token: " + currentToken);
      log("SIMULATED DELIVERY — reset link: " + link);
      verificationView();
    }
  });
  document.getElementById("login-link").addEventListener("click", (event) => { event.preventDefault(); loginView(); });
}

function verificationView() {
  screen.innerHTML = '<h2>Verify recovery code</h2><p>Open the simulated reset link from the Logs panel, or enter its code here manually.</p><form id="verify-form"><label for="token">Recovery code</label><input id="token" name="token" type="text" autocomplete="one-time-code" maxlength="128" required><button type="submit">Verify code</button></form><p id="status" class="status" role="status"></p><nav><a href="#recover" id="recover-link">Request another code</a></nav>';
  const tokenInput = document.getElementById("token");
  if (currentToken) tokenInput.value = currentToken;
  document.getElementById("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const token = tokenInput.value.trim();
    const { response, result } = await api("/api/verify-reset", { token });
    if (!response.ok) return setStatus(result.message || "We could not verify that code.", true);
    currentToken = token;
    setStatus("Recovery code verified.", false);
    log("SIMULATED MFA DELIVERY — verification code: " + result.mockMfaCode);
    setTimeout(mfaView, 250);
  });
  document.getElementById("recover-link").addEventListener("click", (event) => { event.preventDefault(); recoveryView(); });
}

function mfaView() {
  screen.innerHTML = '<h2>Confirm your identity</h2><p>A second verification code was sent through the simulated trusted channel. Enter it to continue.</p><form id="mfa-form"><label for="mfa">Verification code</label><input id="mfa" name="mfa" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button type="submit">Confirm identity</button></form><p id="status" class="status" role="status"></p>';
  document.getElementById("mfa-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = document.getElementById("mfa").value.trim();
    const { response, result } = await api("/api/verify-mfa", { code });
    if (!response.ok) return setStatus(result.message || "We could not verify that code.", true);
    passwordView();
  });
}

function passwordView() {
  screen.innerHTML = '<h2>Create a new password</h2><p>Your password must have at least 12 characters, including uppercase and lowercase letters, a number, and a symbol.</p><form id="password-form"><label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" maxlength="128" required><label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" maxlength="128" required><button type="submit">Save new password</button></form><p id="status" class="status" role="status"></p>';
  document.getElementById("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = document.getElementById("password").value;
    const confirm = document.getElementById("confirm").value;
    if (password !== confirm) return setStatus("The password entries do not match.", true);
    const { response, result } = await api("/api/update-password", { password });
    if (!response.ok) return setStatus(result.message || "Your password could not be saved.", true);
    confirmationView();
  });
}

function confirmationView() {
  screen.innerHTML = '<h2>Password updated</h2><p>Your recovery code is no longer valid. Sign in using your new password to review and accept the updated privacy conditions.</p><button id="continue-login">Continue to sign in</button>';
  document.getElementById("continue-login").addEventListener("click", loginView);
}

function loginView() {
  screen.innerHTML = '<h2>Sign in</h2><p>Sign in to accept the updated privacy conditions.</p><form id="login-form"><label for="login-email">Account email</label><input id="login-email" type="email" autocomplete="username" maxlength="254" required><label for="login-password">Password</label><input id="login-password" type="password" autocomplete="current-password" maxlength="128" required><button type="submit">Sign in securely</button></form><p id="status" class="status" role="status"></p><nav><a href="#recover" id="forgot-link">Forgot password?</a></nav>';
  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = document.getElementById("login-email").value;
    const password = document.getElementById("login-password").value;
    const { response, result } = await api("/api/login", { email, password });
    if (!response.ok) return setStatus(result.message || "Sign-in was not successful.", true);
    if (result.privacyAccepted) portalView(); else privacyView();
  });
  document.getElementById("forgot-link").addEventListener("click", (event) => { event.preventDefault(); recoveryView(); });
}

function privacyView() {
  screen.innerHTML = '<h2>Updated privacy conditions</h2><p>Please review the updated conditions before hospital authorities can process appointment-related account actions.</p><div class="notice"><strong>Privacy summary:</strong> Your account information is used only to provide healthcare account services and is protected under applicable privacy rules.</div><form id="privacy-form"><label><input id="accept" type="checkbox" required> I have read and accept the updated privacy conditions.</label><button type="submit">Accept conditions</button></form><p id="status" class="status" role="status"></p>';
  document.getElementById("privacy-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!document.getElementById("accept").checked) return setStatus("Please confirm acceptance to continue.", true);
    const { response, result } = await api("/api/accept-privacy", { accepted: true });
    if (!response.ok) return setStatus(result.message || "We could not save your choice.", true);
    portalView();
  });
}

async function portalView() {
  const { response } = await api("/api/portal-check", {});
  if (!response.ok) return loginView();
  screen.innerHTML = '<h2>Privacy conditions accepted</h2><p>Your authenticated session has recorded your acceptance. Hospital staff can now continue the appointment process through their authorized systems.</p><p>No personal records are displayed in this recovery portal.</p><button id="logout" class="secondary">Sign out</button>';
  document.getElementById("logout").addEventListener("click", async () => {
    await api("/api/logout", {});
    recoveryView();
  });
}

// Simulated reset-link route/query: only the token value is read as text and submitted through the protected API.
const linkToken = new URLSearchParams(location.search).get("token");
if (location.pathname === "/reset" && linkToken) {
  currentToken = linkToken;
  verificationView();
} else if (location.hash === "#login") {
  loginView();
} else {
  recoveryView();
}
</script>
</body>
</html>`;
  return html;
}

async function apiResponse(request: Request, path: string): Promise<Response> {
  const session = sessionFrom(request);
  if (!validCsrf(request, session)) {
    return json({ message: "Your secure session has expired. Please refresh the page and try again." }, 403);
  }
  const body = await bodyOf(request);
  if (!body) return json({ message: "The request could not be processed." }, 400);

  // Security Requirement 4: generic response and throttling prevent account enumeration and reset abuse.
  if (path === "/api/reset-request") {
    const email = body.email;
    const displayToken = randomToken(32);
    const isAllowed = !limited(session.resetRequests, 3);
    if (isAllowed && validEmail(email) && email.toLowerCase() === account.email) {
      const tokenHash = await sha256(displayToken);
      resets.set(tokenHash, {
        accountId: account.id,
        expires: Date.now() + RESET_MS,
        mfaAttempts: [],
        used: false,
      });
    }
    return json({
      message: "If the account is eligible, recovery instructions have been sent.",
      // A token is returned for every request in this test-only mock, avoiding reset-request enumeration.
      mockToken: displayToken,
    });
  }

  if (path === "/api/verify-reset") {
    const token = body.token;
    if (typeof token !== "string" || token.length < 32 || token.length > 128 || limited(session.verifyAttempts, 5)) {
      return json({ message: "We could not verify that recovery code. Request a new code if needed." }, 400);
    }
    const tokenHash = await sha256(token);
    const record = resets.get(tokenHash);
    if (!record || record.used || record.expires < Date.now() || (record.claimedBy && record.claimedBy !== session.id)) {
      return json({ message: "We could not verify that recovery code. Request a new code if needed." }, 400);
    }
    record.claimedBy = session.id;
    session.recoveryTokenHash = tokenHash;
    return json({ message: "Recovery code verified.", mockMfaCode: "246810" });
  }

  if (path === "/api/verify-mfa") {
    const tokenHash = session.recoveryTokenHash;
    const record = tokenHash ? resets.get(tokenHash) : undefined;
    const code = body.code;
    if (!record || record.used || record.expires < Date.now() || record.claimedBy !== session.id ||
      typeof code !== "string" || !/^\d{6}$/.test(code) || limited(record.mfaAttempts, 5) || code !== "246810") {
      return json({ message: "We could not verify that code. Request a new recovery code if needed." }, 400);
    }
    record.mfaVerifiedBy = session.id;
    return json({ message: "Identity confirmed." });
  }

  if (path === "/api/update-password") {
    const tokenHash = session.recoveryTokenHash;
    const record = tokenHash ? resets.get(tokenHash) : undefined;
    if (!record || record.used || record.expires < Date.now() ||
      record.claimedBy !== session.id || record.mfaVerifiedBy !== session.id || record.accountId !== account.id) {
      return json({ message: "This recovery session is no longer valid. Please start again." }, 403);
    }
    if (!validPassword(body.password)) {
      return json({ message: "Use at least 12 characters with uppercase, lowercase, number, and symbol." }, 400);
    }
    // Security Requirement 4: bcrypt hash replaces the old hash; the raw password is never retained.
    account.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
    record.used = true; // Security Requirement 3: random reset token is single-use.
    session.recoveryTokenHash = undefined;
    return json({ message: "Password updated." });
  }

  if (path === "/api/login") {
    const email = body.email;
    const password = body.password;
    const now = Date.now();
    const locallyLimited = limited(session.loginAttempts, 5);
    const matchingAccount = validEmail(email) && email.toLowerCase() === account.email;
    const locked = account.lockedUntil > now;
    let verified = false;
    if (!locallyLimited && !locked && matchingAccount && typeof password === "string" && password.length <= 128) {
      verified = await Bun.password.verify(password, account.passwordHash);
    }
    if (!verified) {
      if (matchingAccount) {
        account.failedLogins++;
        if (account.failedLogins >= 5) {
          account.lockedUntil = now + LIMIT_WINDOW_MS;
          account.failedLogins = 0;
        }
      }
      return json({ message: "Sign-in was not successful. Please check your details or try again later." }, 401);
    }
    account.failedLogins = 0;
    session.authenticatedAccountId = account.id;
    session.privacyAccepted = false;
    return json({ message: "Signed in.", privacyAccepted: session.privacyAccepted });
  }

  // Security Requirement 1: authenticated server-side checks have no client-supplied account identifier (no IDOR).
  if (path === "/api/accept-privacy") {
    if (session.authenticatedAccountId !== account.id || body.accepted !== true) {
      return json({ message: "You must sign in before accepting conditions." }, 403);
    }
    session.privacyAccepted = true;
    return json({ message: "Conditions accepted." });
  }

  if (path === "/api/portal-check") {
    if (session.authenticatedAccountId !== account.id || !session.privacyAccepted) {
      return json({ message: "Access is not available." }, 403);
    }
    return json({ message: "Authorized." });
  }

  if (path === "/api/logout") {
    session.authenticatedAccountId = undefined;
    session.privacyAccepted = false;
    session.recoveryTokenHash = undefined;
    return json({ message: "Signed out." });
  }

  return json({ message: "Not found." }, 404);
}

const port = Number(Bun.env.PORT || 3000);

Bun.serve({
  port,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "POST" && url.pathname.startsWith("/api/")) {
        return await apiResponse(request, url.pathname);
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/reset")) {
        let session = sessionFrom(request);
        let created = false;
        if (!session) {
          session = newSession();
          sessions.set(session.id, session);
          created = true;
        }
        const response = new Response(page(session), { headers: securityHeaders(randomToken(16)) });
        if (created) response.headers.append("Set-Cookie", cookieFor(session));
        return response;
      }
      return new Response("Not found", { status: 404, headers: securityHeaders(randomToken(16)) });
    } catch {
      // Security Requirement 3: no stack traces or debug details are sent to clients.
      return new Response("Service unavailable", { status: 503, headers: securityHeaders(randomToken(16)) });
    }
  },
});

console.log(`Hospital recovery demo available at https://localhost:${port}`);
