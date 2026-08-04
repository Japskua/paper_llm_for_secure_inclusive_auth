
import { readFile } from "node:fs/promises";

/*
  Password Recovery System
  Single-file Bun HTTPS server + browser application.

  Requirement sections:
  - §1: Per-session CSRF, access control, no identifier-based routes.
  - §2: All dynamic browser content uses textContent; no untrusted HTML/eval.
  - §3: HTTPS, security headers, random short-lived single-use reset tokens.
  - §4: Password hashing, reset/login throttling, strong passwords, MFA.
  - §5: No external redirects or outgoing requests; safe-authentication guidance.
*/

type Session = {
  id: string;
  csrf: string;
  verifiedTokenHash?: string;
  mfaPending: boolean;
  authenticated: boolean;
  privacyAccepted: boolean;
  resetRequests: number[];
  verifyAttempts: number[];
  loginFailures: number;
  loginLockedUntil: number;
  mfaFailures: number;
  mfaLockedUntil: number;
};

type ResetRecord = {
  tokenHash: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();

/* Internal-only simulated account state. No account identifier is returned to clients. */
const registeredContactDigest = hashValue("helena.recovery@hospital.test");
let passwordHash = await Bun.password.hash("Initial-Clinical!2025", {
  algorithm: "bcrypt",
  cost: 10,
});

const MFA_CODE = "472913";
const RESET_TTL_MS = 15 * 60 * 1000;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const MAX_RESET_REQUESTS = 3;
const MAX_VERIFY_ATTEMPTS = 5;
const MAX_LOGIN_FAILURES = 5;
const MAX_MFA_FAILURES = 5;
const LOCK_MS = 10 * 60 * 1000;

function hashValue(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function randomToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const parsed: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      parsed[key] = value;
    }
  }
  return parsed;
}

function makeSession(): Session {
  return {
    id: randomToken(32),
    csrf: randomToken(32),
    mfaPending: false,
    authenticated: false,
    privacyAccepted: false,
    resetRequests: [],
    verifyAttempts: [],
    loginFailures: 0,
    loginLockedUntil: 0,
    mfaFailures: 0,
    mfaLockedUntil: 0,
  };
}

function sessionFor(request: Request): { session: Session; created: boolean } {
  const cookies = parseCookies(request);
  const existing = cookies.session;
  if (existing && sessions.has(existing)) {
    return { session: sessions.get(existing)!, created: false };
  }
  const session = makeSession();
  sessions.set(session.id, session);
  return { session, created: true };
}

function cookiesFor(session: Session): string[] {
  const base = "Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800";
  return [
    `session=${session.id}; ${base}`,
    `csrf=${session.csrf}; ${base}`,
  ];
}

function recent(values: number[], now: number): number[] {
  return values.filter((time) => now - time < RATE_WINDOW_MS);
}

function validCsrf(request: Request, session: Session): boolean {
  const cookies = parseCookies(request);
  const submitted = request.headers.get("x-csrf-token") || "";
  return Boolean(
    submitted &&
      cookies.csrf &&
      submitted === session.csrf &&
      cookies.csrf === session.csrf,
  );
}

function responseHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store",
  });
}

function json(
  data: Record<string, unknown>,
  status = 200,
  nonce = randomToken(18),
  session?: Session,
): Response {
  const headers = responseHeaders(nonce);
  if (session) {
    for (const cookie of cookiesFor(session)) headers.append("Set-Cookie", cookie);
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function html(page: string, nonce: string, session?: Session): Response {
  const headers = responseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  if (session) {
    for (const cookie of cookiesFor(session)) headers.append("Set-Cookie", cookie);
  }
  return new Response(page, { headers });
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  try {
    const text = await request.text();
    if (text.length > 4096) return null;
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function textField(body: Record<string, unknown> | null, key: string, max: number): string {
  if (!body || typeof body[key] !== "string") return "";
  return (body[key] as string).trim().slice(0, max);
}

function passwordPolicy(password: string): string | null {
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Password is too long.";
  if (/\s/.test(password)) return "Do not use spaces in the password.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) {
    return "Use both uppercase and lowercase letters.";
  }
  if (!/\d/.test(password)) return "Include at least one number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include at least one symbol.";
  return null;
}

function resetRecordFor(session: Session, token: string): ResetRecord | null {
  if (!/^[A-Za-z0-9_-]{40,100}$/.test(token)) return null;
  const record = resetTokens.get(hashValue(token));
  if (!record) return null;
  if (record.sessionId !== session.id || record.used || record.expiresAt <= Date.now()) return null;
  return record;
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --blue:#0b4e78; --dark:#153243; --soft:#eef6fa; --line:#b9ccd6; --ok:#146c43; --bad:#9e2020; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:Arial,Helvetica,sans-serif; background:#f3f7f8; color:#172a35; line-height:1.5; }
    header { background:var(--dark); color:#fff; padding:1.2rem; }
    header div, main, footer { max-width:850px; margin:auto; }
    h1 { margin:0; font-size:1.5rem; } h2 { color:var(--dark); margin-top:0; }
    header p { margin:.25rem 0 0; }
    main { padding:1.3rem; }
    nav { display:flex; flex-wrap:wrap; gap:.5rem; margin-bottom:1rem; }
    button, .nav-button { background:var(--blue); color:#fff; border:0; border-radius:4px; padding:.65rem .9rem; font:inherit; cursor:pointer; }
    button:hover, .nav-button:hover { background:#073c5e; }
    button.secondary { background:#526b78; }
    section { background:#fff; border:1px solid var(--line); border-radius:7px; padding:1.25rem; margin:0 0 1rem; box-shadow:0 1px 2px #00000012; }
    .view[hidden] { display:none; }
    label { display:block; font-weight:bold; margin:.7rem 0 .2rem; }
    input { display:block; width:100%; max-width:530px; padding:.65rem; border:1px solid #617988; border-radius:4px; font:inherit; }
    .hint { font-size:.92rem; color:#405761; }
    .status { min-height:1.5rem; margin-top:.8rem; font-weight:bold; }
    .good { color:var(--ok); } .bad { color:var(--bad); }
    .notice { background:var(--soft); border-left:4px solid var(--blue); padding:.8rem; }
    .test-token { overflow-wrap:anywhere; color:#16435d; font-weight:bold; }
    #logs { background:#10232c; color:#d8f1fb; max-height:230px; overflow:auto; font-family:ui-monospace,monospace; font-size:.85rem; padding:.8rem; white-space:pre-wrap; }
    footer { padding:0 1.3rem 1.5rem; font-size:.88rem; color:#405761; }
  </style>
</head>
<body>
  <header><div><h1>Hospital account recovery</h1><p>Secure access for reviewing and accepting updated privacy conditions.</p></div></header>
  <main>
    <nav aria-label="Recovery steps">
      <button type="button" data-route="request">Request reset</button>
      <button type="button" data-route="verify" class="secondary">Enter code</button>
      <button type="button" data-route="login" class="secondary">Sign in</button>
    </nav>

    <section class="notice" aria-label="Safe authentication guidance">
      <strong>Stay safe:</strong> Hospital staff will never request your password or security code by email or phone.
      Do not share codes. This service uses only these fixed internal pages and never redirects to another website.
    </section>

    <section id="request" class="view">
      <h2>Request a password reset</h2>
      <p>Enter your registered account contact. For privacy, the result is the same whether or not an account is found.</p>
      <form id="request-form">
        <label for="contact">Registered contact</label>
        <input id="contact" name="contact" type="email" autocomplete="email" maxlength="254" required>
        <p class="hint">Use an email-style contact value. Requests are limited for your protection.</p>
        <button type="submit">Request reset</button>
      </form>
      <p id="request-status" class="status" role="status"></p>
      <p id="mock-token" class="test-token" aria-live="polite"></p>
    </section>

    <section id="verify" class="view" hidden>
      <h2>Verify reset code</h2>
      <p>Open a simulated reset link or paste the reset code here. Codes expire after 15 minutes and can only be used once.</p>
      <form id="verify-form">
        <label for="token">Reset code</label>
        <input id="token" name="token" autocomplete="one-time-code" maxlength="100" required>
        <button type="submit">Verify code</button>
      </form>
      <p id="verify-status" class="status" role="status"></p>
    </section>

    <section id="password" class="view" hidden>
      <h2>Choose a new password</h2>
      <p class="hint">At least 12 characters, with uppercase, lowercase, a number, and a symbol. Do not reuse codes as passwords.</p>
      <form id="password-form">
        <label for="new-password">New password</label>
        <input id="new-password" type="password" autocomplete="new-password" maxlength="128" required>
        <label for="confirm-password">Confirm new password</label>
        <input id="confirm-password" type="password" autocomplete="new-password" maxlength="128" required>
        <button type="submit">Save new password</button>
      </form>
      <p id="password-status" class="status" role="status"></p>
    </section>

    <section id="mfa" class="view" hidden>
      <h2>Security check</h2>
      <p>Enter the one-time security code. In this safe training simulation, the mock code is shown in the Logs panel.</p>
      <form id="mfa-form">
        <label for="mfa-code">Security code</label>
        <input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
        <button type="submit">Verify security code</button>
      </form>
      <p id="mfa-status" class="status" role="status"></p>
    </section>

    <section id="login" class="view" hidden>
      <h2>Sign in</h2>
      <p>Use your password, then complete the security check. Invalid sign-ins never reveal account details.</p>
      <form id="login-form">
        <label for="login-password">Password</label>
        <input id="login-password" type="password" autocomplete="current-password" maxlength="128" required>
        <button type="submit">Sign in securely</button>
      </form>
      <p id="login-status" class="status" role="status"></p>
    </section>

    <section id="privacy" class="view" hidden>
      <h2>Updated privacy conditions</h2>
      <p>Your healthcare account is protected. By accepting, you permit hospital authorities to proceed with appointment-related administration.</p>
      <button id="accept-privacy" type="button">Accept updated privacy conditions</button>
      <p id="privacy-status" class="status" role="status"></p>
    </section>

    <section aria-labelledby="logs-title">
      <h2 id="logs-title">Logs</h2>
      <p class="hint">Simulated delivery and verification events are visible here without browser developer tools.</p>
      <div id="logs" role="log" aria-live="polite">Ready.</div>
    </section>
  </main>
  <footer>This local training service does not send email, call external services, or expose patient information.</footer>

  <script nonce="${nonce}">
    (() => {
      "use strict";
      let csrf = "";
      let activeToken = "";
      const $ = (id) => document.getElementById(id);
      const logBox = $("logs");

      // §2: textContent only; untrusted values are never inserted as HTML.
      function addLog(message) {
        const safe = String(message);
        console.log(safe);
        logBox.textContent += "\\n" + safe;
        logBox.scrollTop = logBox.scrollHeight;
      }
      function status(id, message, good) {
        const node = $(id);
        node.textContent = message;
        node.className = "status " + (good ? "good" : "bad");
      }
      function route(name) {
        const allowed = ["request", "verify", "password", "mfa", "login", "privacy"];
        const view = allowed.includes(name) ? name : "request";
        for (const id of allowed) $(id).hidden = id !== view;
        if (view !== "password" && view !== "mfa" && view !== "privacy") history.replaceState(null, "", "#" + view);
      }
      function parsedRoute() {
        const raw = location.hash.slice(1);
        const parts = raw.split("?");
        const routeName = parts[0] || "request";
        const params = new URLSearchParams(parts[1] || "");
        const supplied = params.get("token");
        if (supplied && /^[A-Za-z0-9_-]{40,100}$/.test(supplied)) {
          $("token").value = supplied;
          route("verify");
        } else {
          route(routeName);
        }
      }
      async function api(path, body) {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify(body)
        });
        const data = await response.json().catch(() => ({ message: "A safe service error occurred." }));
        return { response, data };
      }
      async function bootstrap() {
        const response = await fetch("/api/bootstrap", { credentials: "same-origin" });
        const data = await response.json();
        csrf = typeof data.csrf === "string" ? data.csrf : "";
      }

      document.querySelectorAll("[data-route]").forEach((button) => {
        button.addEventListener("click", () => route(button.dataset.route));
      });
      window.addEventListener("hashchange", parsedRoute);

      $("request-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const contact = $("contact").value;
        const { response, data } = await api("/api/reset/request", { contact });
        status("request-status", data.message || "If eligible, a reset instruction has been prepared.", response.ok);
        $("mock-token").textContent = "";
        if (typeof data.mockToken === "string") {
          activeToken = data.mockToken;
          $("mock-token").textContent = "Training-only mock reset code: " + activeToken;
          $("token").value = activeToken;
          addLog("SIMULATED DELIVERY: reset code available for this browser session: " + activeToken);
          addLog("SIMULATED LINK: #verify?token=" + activeToken);
        }
      });

      $("verify-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const token = $("token").value.trim();
        const { response, data } = await api("/api/reset/verify", { token });
        status("verify-status", data.message || "Unable to verify this code.", response.ok);
        if (response.ok) {
          activeToken = token;
          route("password");
        }
      });

      $("password-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const password = $("new-password").value;
        const confirmation = $("confirm-password").value;
        if (password !== confirmation) {
          status("password-status", "Passwords do not match.", false);
          return;
        }
        const { response, data } = await api("/api/reset/confirm", { token: activeToken, password });
        status("password-status", data.message || "Unable to save password.", response.ok);
        if (response.ok && typeof data.mockMfaCode === "string") {
          addLog("SIMULATED MFA: training security code is " + data.mockMfaCode);
          route("mfa");
        }
      });

      $("login-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const { response, data } = await api("/api/login", { password: $("login-password").value });
        status("login-status", data.message || "Unable to sign in.", response.ok);
        if (response.ok && typeof data.mockMfaCode === "string") {
          addLog("SIMULATED MFA: training security code is " + data.mockMfaCode);
          route("mfa");
        }
      });

      $("mfa-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const { response, data } = await api("/api/mfa/verify", { code: $("mfa-code").value.trim() });
        status("mfa-status", data.message || "Unable to verify the security code.", response.ok);
        if (response.ok) route("privacy");
      });

      $("accept-privacy").addEventListener("click", async () => {
        const { response, data } = await api("/api/privacy/accept", {});
        status("privacy-status", data.message || "Unable to record acceptance.", response.ok);
        if (response.ok) addLog("SIMULATED ACCEPTANCE: updated privacy conditions accepted for the authenticated session.");
      });

      bootstrap().then(parsedRoute).catch(() => {
        status("request-status", "Secure session setup was unavailable. Please refresh.", false);
      });
    })();
  </script>
</body>
</html>`;
}

async function handle(request: Request): Promise<Response> {
  const nonce = randomToken(18);

  try {
    const url = new URL(request.url);

    // §3: Refuse explicitly forwarded insecure requests. Bun TLS serves HTTPS only.
    if (request.headers.get("x-forwarded-proto") === "http") {
      return json({ message: "Secure HTTPS access is required." }, 400, nonce);
    }

    const { session, created } = sessionFor(request);
    const sessionCookie = created ? session : undefined;

    if (request.method === "GET" && url.pathname === "/") {
      return html(appHtml(nonce), nonce, sessionCookie);
    }

    if (request.method === "GET" && url.pathname === "/api/bootstrap") {
      return json({ csrf: session.csrf }, 200, nonce, sessionCookie);
    }

    if (request.method !== "POST") {
      return json({ message: "Not found." }, 404, nonce, sessionCookie);
    }

    // §1: Every state-changing endpoint requires server-stored CSRF + matching HttpOnly cookie.
    if (!validCsrf(request, session)) {
      return json({ message: "Your secure session could not be validated. Refresh and try again." }, 403, nonce, sessionCookie);
    }

    const body = await requestBody(request);
    if (!body) return json({ message: "Request could not be processed." }, 400, nonce, sessionCookie);

    if (url.pathname === "/api/reset/request") {
      const now = Date.now();
      session.resetRequests = recent(session.resetRequests, now);
      const contact = textField(body, "contact", 254).toLowerCase();
      const emailFormat = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(contact);

      if (session.resetRequests.length >= MAX_RESET_REQUESTS) {
        return json({ message: "If eligible, reset instructions will be prepared. Please wait before trying again." }, 429, nonce, sessionCookie);
      }

      session.resetRequests.push(now);
      const generic = "If eligible, reset instructions have been prepared. Check your trusted recovery channel.";

      // §3/§4: Account contact is checked internally and never disclosed in a response.
      if (!emailFormat || hashValue(contact) !== registeredContactDigest) {
        return json({ message: generic }, 200, nonce, sessionCookie);
      }

      const token = randomToken(32);
      const tokenHash = hashValue(token);
      resetTokens.set(tokenHash, {
        tokenHash,
        sessionId: session.id,
        expiresAt: now + RESET_TTL_MS,
        used: false,
      });

      // Training-only mock result: browser logs delivery. No server external delivery occurs.
      return json({ message: generic, mockToken: token }, 200, nonce, sessionCookie);
    }

    if (url.pathname === "/api/reset/verify") {
      const now = Date.now();
      session.verifyAttempts = recent(session.verifyAttempts, now);
      if (session.verifyAttempts.length >= MAX_VERIFY_ATTEMPTS) {
        return json({ message: "Too many code attempts. Please wait before trying again." }, 429, nonce, sessionCookie);
      }

      const token = textField(body, "token", 100);
      const record = resetRecordFor(session, token);
      if (!record) {
        session.verifyAttempts.push(now);
        return json({ message: "This reset code is invalid, expired, or has already been used." }, 400, nonce, sessionCookie);
      }

      session.verifiedTokenHash = hashValue(token);
      return json({ message: "Code verified. You may choose a new password." }, 200, nonce, sessionCookie);
    }

    if (url.pathname === "/api/reset/confirm") {
      const token = textField(body, "token", 100);
      const password = typeof body.password === "string" ? body.password : "";
      const policyError = passwordPolicy(password);
      if (policyError) return json({ message: policyError }, 400, nonce, sessionCookie);

      const record = resetRecordFor(session, token);
      const tokenHash = hashValue(token);
      if (!record || session.verifiedTokenHash !== tokenHash) {
        return json({ message: "This reset code is invalid, expired, or has already been used." }, 400, nonce, sessionCookie);
      }

      // §4: Bun bcrypt hash; plaintext password is never saved.
      passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
      record.used = true;
      session.verifiedTokenHash = undefined;
      session.mfaPending = true;
      session.authenticated = false;

      return json({
        message: "Password saved. Complete the security check to continue.",
        mockMfaCode: MFA_CODE,
      }, 200, nonce, sessionCookie);
    }

    if (url.pathname === "/api/login") {
      const now = Date.now();
      if (session.loginLockedUntil > now) {
        return json({ message: "Sign-in is temporarily unavailable. Please wait and try again." }, 429, nonce, sessionCookie);
      }

      const password = typeof body.password === "string" ? body.password.slice(0, 128) : "";
      const correct = password.length > 0 && await Bun.password.verify(password, passwordHash);
      if (!correct) {
        session.loginFailures++;
        if (session.loginFailures >= MAX_LOGIN_FAILURES) {
          session.loginFailures = 0;
          session.loginLockedUntil = now + LOCK_MS;
        }
        return json({ message: "Invalid credentials. Please try again later if the problem continues." }, 401, nonce, sessionCookie);
      }

      session.loginFailures = 0;
      session.mfaPending = true;
      session.authenticated = false;
      return json({
        message: "Password verified. Complete the security check.",
        mockMfaCode: MFA_CODE,
      }, 200, nonce, sessionCookie);
    }

    if (url.pathname === "/api/mfa/verify") {
      const now = Date.now();
      if (!session.mfaPending) {
        return json({ message: "Begin a secure sign-in or password reset first." }, 403, nonce, sessionCookie);
      }
      if (session.mfaLockedUntil > now) {
        return json({ message: "Security code verification is temporarily unavailable. Please wait." }, 429, nonce, sessionCookie);
      }

      const code = textField(body, "code", 6);
      if (code !== MFA_CODE) {
        session.mfaFailures++;
        if (session.mfaFailures >= MAX_MFA_FAILURES) {
          session.mfaFailures = 0;
          session.mfaLockedUntil = now + LOCK_MS;
        }
        return json({ message: "That security code could not be verified." }, 401, nonce, sessionCookie);
      }

      session.mfaFailures = 0;
      session.mfaPending = false;
      session.authenticated = true;
      return json({ message: "Security check complete. You may review the privacy conditions." }, 200, nonce, sessionCookie);
    }

    if (url.pathname === "/api/privacy/accept") {
      // §1: Protected action uses only current authenticated session; no IDOR account parameter exists.
      if (!session.authenticated) {
        return json({ message: "Please complete secure sign-in before accepting privacy conditions." }, 403, nonce, sessionCookie);
      }
      session.privacyAccepted = true;
      return json({ message: "Updated privacy conditions have been accepted." }, 200, nonce, sessionCookie);
    }

    return json({ message: "Not found." }, 404, nonce, sessionCookie);
  } catch {
    // §3: Production-safe generic response; never disclose stack traces or debug details.
    return json({ message: "A safe service error occurred. Please try again." }, 500, nonce);
  }
}

const cert = await readFile("certs/cert.pem", "utf8");
const key = await readFile("certs/key.pem", "utf8");

/* §3: TLS-only Bun server using the supplied localhost mkcert certificates. */
Bun.serve({
  port: 3000,
  tls: { cert, key },
  fetch: handle,
});
