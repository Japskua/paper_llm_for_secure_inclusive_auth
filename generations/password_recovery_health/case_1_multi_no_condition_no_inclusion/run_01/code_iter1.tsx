
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * Password Recovery System, single-file Bun server + SPA.
 * Security requirement sections are labelled S1-S5 in comments below.
 */

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_TTL_MS = 30 * 60 * 1000;
const RESET_TTL_MS = 15 * 60 * 1000;
const MOCK_ACCOUNT_IDENTIFIER = "helena.patient@hospital.test"; // Never returned to a client.
const MFA_TEST_CODE = "246810"; // Deterministic mock delivery code for this academic demo.

type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  requestAttempts: number[];
  verifyAttempts: number[];
  mfaAttempts: number[];
  resetKey?: string;
  mfaComplete: boolean;
};

type ResetRecord = {
  digest: Buffer;
  expiresAt: number;
  used: boolean;
  boundSessionId?: string;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
let activeResetKey: string | undefined;

// S4: Passwords are only stored as Argon2 hashes; no plaintext password is retained.
let mockPasswordHash = await Bun.password.hash("Initial-Demo-Password-Only!", {
  algorithm: "argon2id",
});

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

function safeEqual(left: Buffer | string, right: Buffer | string): boolean {
  const a = Buffer.isBuffer(left) ? left : Buffer.from(left);
  const b = Buffer.isBuffer(right) ? right : Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function makeToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const header = request.headers.get("cookie") || "";
  for (const item of header.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) {
      const key = item.slice(0, index).trim();
      const value = item.slice(index + 1).trim();
      if (/^[A-Za-z0-9_-]+$/.test(value)) result[key] = value;
    }
  }
  return result;
}

function newSession(): Session {
  const session: Session = {
    id: makeToken(32),
    csrf: makeToken(32),
    expiresAt: Date.now() + SESSION_TTL_MS,
    requestAttempts: [],
    verifyAttempts: [],
    mfaAttempts: [],
    mfaComplete: false,
  };
  sessions.set(session.id, session);
  return session;
}

function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const sid = parseCookies(request).sid;
  const current = sid ? sessions.get(sid) : undefined;
  if (current && current.expiresAt > Date.now()) {
    return { session: current, isNew: false };
  }
  if (sid) sessions.delete(sid);
  return { session: newSession(), isNew: true };
}

function sessionCookie(session: Session): string {
  // S1/S3/S4: secure, HttpOnly, SameSite session cookie.
  return `sid=${session.id}; Path=/; Max-Age=${Math.floor(
    SESSION_TTL_MS / 1000,
  )}; Secure; HttpOnly; SameSite=Strict`;
}

function nonce(): string {
  return randomBytes(18).toString("base64");
}

// S3: Uniform production security headers. CSP permits only this response's inline SPA.
function baseHeaders(scriptNonce: string): Headers {
  return new Headers({
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": [
      "default-src 'none'",
      `script-src 'nonce-${scriptNonce}'`,
      `style-src 'nonce-${scriptNonce}'`,
      "connect-src 'self'",
      "img-src 'self'",
      "font-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
}

function response(
  body: string,
  options: {
    status?: number;
    type?: string;
    session?: Session;
    nonce?: string;
  } = {},
): Response {
  const n = options.nonce || nonce();
  const headers = baseHeaders(n);
  headers.set("Content-Type", options.type || "text/plain; charset=utf-8");
  if (options.session) headers.set("Set-Cookie", sessionCookie(options.session));
  return new Response(body, { status: options.status || 200, headers });
}

function json(
  data: Record<string, unknown>,
  status: number,
  session: Session,
): Response {
  return response(JSON.stringify(data), {
    status,
    type: "application/json; charset=utf-8",
    session,
  });
}

function limited(bucket: number[], maximum: number, windowMs: number): boolean {
  const now = Date.now();
  while (bucket.length && bucket[0] < now - windowMs) bucket.shift();
  if (bucket.length >= maximum) return true;
  bucket.push(now);
  return false;
}

// S1: Every state-changing request requires a per-session CSRF token and same-origin request.
function validCsrf(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  const origin = request.headers.get("origin");
  const expectedOrigin = new URL(request.url).origin;
  return (
    origin === expectedOrigin &&
    supplied.length > 10 &&
    safeEqual(supplied, session.csrf)
  );
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.startsWith("application/json")) return null;
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function validIdentifier(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length < 3 ||
    normalized.length > 120 ||
    !/^[a-z0-9][a-z0-9._+@-]*[a-z0-9]$/i.test(normalized)
  ) {
    return null;
  }
  return normalized;
}

function validResetToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return /^[A-Za-z0-9_-]{30,100}$/.test(value) ? value : null;
}

function resetForSession(session: Session): ResetRecord | null {
  if (!session.resetKey) return null;
  const reset = resets.get(session.resetKey);
  if (
    !reset ||
    reset.used ||
    reset.expiresAt <= Date.now() ||
    reset.boundSessionId !== session.id
  ) {
    return null;
  }
  return reset;
}

function passwordProblem(password: unknown): string | null {
  if (typeof password !== "string") return "Enter a new password.";
  if (password.length < 12 || password.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[^A-Za-z0-9\s]/.test(password) ||
    /\s/.test(password)
  ) {
    return "Use uppercase, lowercase, a number, and a symbol, with no spaces.";
  }
  return null;
}

function htmlPage(pageNonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Recovery</title>
  <style nonce="${pageNonce}">
    :root { color-scheme: light; --blue:#075a9d; --navy:#07385f; --ink:#17212b; --soft:#eef5f9; --line:#c9d7e1; --danger:#a51d2d; --ok:#146c43; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--soft); color:var(--ink); font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
    header { background:var(--navy); color:white; padding:1.2rem 1rem; }
    header div, main, footer { max-width:760px; margin:auto; }
    header h1 { margin:0; font-size:1.35rem; }
    header p { margin:.25rem 0 0; font-size:.94rem; }
    main { padding:1.5rem 1rem 2rem; }
    section.card, aside, .logs { background:white; border:1px solid var(--line); border-radius:8px; padding:1.25rem; margin-bottom:1rem; box-shadow:0 1px 2px #1231; }
    h2 { margin-top:0; color:var(--navy); font-size:1.3rem; }
    label { display:block; font-weight:bold; margin:.8rem 0 .25rem; }
    input { width:100%; padding:.72rem; border:1px solid #8599a8; border-radius:4px; font:inherit; }
    button, .link-button { margin-top:1rem; padding:.68rem 1rem; border:0; border-radius:4px; background:var(--blue); color:white; font:inherit; font-weight:bold; cursor:pointer; text-decoration:none; display:inline-block; }
    button.secondary { background:#526571; margin-left:.5rem; }
    button:focus, input:focus, a:focus { outline:3px solid #e6a800; outline-offset:2px; }
    .hint { font-size:.92rem; color:#40525e; }
    .message { min-height:1.5rem; margin:.8rem 0 0; font-weight:bold; }
    .error { color:var(--danger); } .success { color:var(--ok); }
    [hidden] { display:none !important; }
    aside { border-left:5px solid var(--blue); }
    aside h2 { font-size:1.08rem; }
    .logs { background:#101820; color:#dbeeff; }
    .logs h2 { color:white; font-size:1.05rem; }
    #log-output { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font: .82rem ui-monospace, SFMono-Regular, Consolas, monospace; max-height:180px; overflow:auto; }
    footer { padding:0 1rem 2rem; font-size:.85rem; color:#4e616e; }
  </style>
</head>
<body>
  <header><div><h1>Hospital Account Recovery</h1><p>Secure access to your healthcare account</p></div></header>
  <main>
    <section class="card" id="request-view">
      <h2>Reset your password</h2>
      <p>Enter the email address or account identifier associated with your account.</p>
      <form id="request-form" novalidate>
        <label for="identifier">Email address or account identifier</label>
        <input id="identifier" name="identifier" autocomplete="username" maxlength="120" required>
        <p class="hint">For privacy, the same confirmation is shown whether or not an account can be recovered.</p>
        <button type="submit">Send recovery instructions</button>
      </form>
      <p id="request-message" class="message" role="status" aria-live="polite"></p>
      <a id="reset-link" class="link-button" hidden>Open simulated reset link</a>
      <button id="manual-button" class="secondary" type="button">Enter a recovery code manually</button>
    </section>

    <section class="card" id="verify-view" hidden>
      <h2>Verify recovery code</h2>
      <p>Open the secure recovery link you received, or enter its code below.</p>
      <form id="verify-form" novalidate>
        <label for="reset-token">Recovery code</label>
        <input id="reset-token" name="token" autocomplete="one-time-code" maxlength="100" required>
        <button type="submit">Verify recovery code</button>
        <button id="verify-back" class="secondary" type="button">Back</button>
      </form>
      <p id="verify-message" class="message" role="status" aria-live="polite"></p>
    </section>

    <section class="card" id="mfa-view" hidden>
      <h2>Confirm your identity</h2>
      <p>Enter the six-digit verification code sent through the simulated secure delivery channel.</p>
      <form id="mfa-form" novalidate>
        <label for="mfa-code">Verification code</label>
        <input id="mfa-code" name="mfa" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
        <button type="submit">Confirm code</button>
      </form>
      <p id="mfa-message" class="message" role="status" aria-live="polite"></p>
    </section>

    <section class="card" id="password-view" hidden>
      <h2>Create a strong password</h2>
      <p class="hint">Use 12 or more characters, including uppercase, lowercase, a number, and a symbol. Do not use spaces.</p>
      <form id="password-form" novalidate>
        <label for="new-password">New password</label>
        <input id="new-password" name="password" type="password" autocomplete="new-password" maxlength="128" required>
        <label for="confirm-password">Confirm new password</label>
        <input id="confirm-password" name="confirm" type="password" autocomplete="new-password" maxlength="128" required>
        <button type="submit">Update password</button>
      </form>
      <p id="password-message" class="message" role="status" aria-live="polite"></p>
    </section>

    <section class="card" id="success-view" hidden>
      <h2>Password updated</h2>
      <p>Your password has been updated. You may now return to the hospital account sign-in service and accept the updated privacy conditions.</p>
      <button id="restart-button" type="button">Start another recovery</button>
    </section>

    <aside aria-labelledby="safe-title">
      <h2 id="safe-title">Keep your account safe</h2>
      <p>Hospital staff will never ask for your password or verification code. Never share credentials or codes by email, text message, or phone. Use only this hospital address and do not follow unexpected links.</p>
    </aside>

    <section class="logs" aria-labelledby="logs-title">
      <h2 id="logs-title">Logs</h2>
      <p id="log-output" aria-live="polite">Secure recovery session ready.</p>
    </section>
  </main>
  <footer>Demo recovery service. No patient details, account identifiers, or passwords are displayed.</footer>

  <script nonce="${pageNonce}">
    "use strict";
    // Single-file/no-build client. S2: all dynamic messages use textContent, never HTML insertion.
    const state = { csrf: "", current: "request" };
    const ids = ["request", "verify", "mfa", "password", "success"];
    const logOutput = document.getElementById("log-output");

    function safeLog(message) {
      console.log(message); // Required simulated-delivery browser console logging.
      const line = document.createTextNode("\\n" + message);
      logOutput.appendChild(line);
      logOutput.scrollTop = logOutput.scrollHeight;
    }

    function message(name, text, kind) {
      const element = document.getElementById(name + "-message");
      element.textContent = text;
      element.className = "message " + (kind || "");
    }

    function show(name) {
      state.current = name;
      ids.forEach(function(id) {
        document.getElementById(id + "-view").hidden = id !== name;
      });
      const input = document.querySelector("#" + name + "-view input");
      if (input) input.focus();
    }

    async function api(path, payload) {
      const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
        body: JSON.stringify(payload)
      });
      let data = {};
      try { data = await response.json(); } catch (_) {}
      return { ok: response.ok, status: response.status, data: data };
    }

    async function setup() {
      try {
        const response = await fetch("/api/session", { credentials: "same-origin" });
        const data = await response.json();
        state.csrf = data.csrf;
        const fromLink = new URLSearchParams(location.search).get("reset");
        if (fromLink) {
          document.getElementById("reset-token").value = fromLink;
          show("verify");
          message("verify", "Recovery code loaded from the secure link. Verify it to continue.", "");
          history.replaceState({}, "", "/");
        }
      } catch (_) {
        message("request", "Unable to start a secure recovery session. Please refresh the page.", "error");
      }
    }

    document.getElementById("manual-button").addEventListener("click", function() { show("verify"); });
    document.getElementById("verify-back").addEventListener("click", function() { show("request"); });
    document.getElementById("restart-button").addEventListener("click", function() {
      show("request");
      document.getElementById("request-form").reset();
      document.getElementById("reset-link").hidden = true;
      message("request", "", "");
    });

    document.getElementById("request-form").addEventListener("submit", async function(event) {
      event.preventDefault();
      const identifier = document.getElementById("identifier").value.trim();
      if (identifier.length < 3) {
        message("request", "Enter a valid email address or account identifier.", "error");
        return;
      }
      const result = await api("/api/reset-request", { identifier: identifier });
      if (!result.ok) {
        message("request", result.data.message || "Please wait before trying again.", "error");
        return;
      }
      message("request", result.data.message, "success");
      if (result.data.testToken) {
        safeLog("SIMULATED RESET DELIVERY — recovery code: " + result.data.testToken);
        const link = document.getElementById("reset-link");
        link.href = "/?reset=" + encodeURIComponent(result.data.testToken);
        link.hidden = false;
      }
    });

    document.getElementById("verify-form").addEventListener("submit", async function(event) {
      event.preventDefault();
      const token = document.getElementById("reset-token").value.trim();
      const result = await api("/api/reset-verify", { token: token });
      if (!result.ok) {
        message("verify", result.data.message || "This recovery code cannot be used.", "error");
        return;
      }
      safeLog("SIMULATED MFA DELIVERY — verification code: " + result.data.testMfaCode);
      message("verify", "", "");
      show("mfa");
    });

    document.getElementById("mfa-form").addEventListener("submit", async function(event) {
      event.preventDefault();
      const code = document.getElementById("mfa-code").value.trim();
      const result = await api("/api/mfa-verify", { code: code });
      if (!result.ok) {
        message("mfa", result.data.message || "The verification code cannot be used.", "error");
        return;
      }
      message("mfa", "", "");
      show("password");
    });

    document.getElementById("password-form").addEventListener("submit", async function(event) {
      event.preventDefault();
      const password = document.getElementById("new-password").value;
      const confirm = document.getElementById("confirm-password").value;
      if (password !== confirm) {
        message("password", "The password confirmation does not match.", "error");
        return;
      }
      const result = await api("/api/password-update", { password: password });
      if (!result.ok) {
        message("password", result.data.message || "Password update could not be completed.", "error");
        return;
      }
      document.getElementById("password-form").reset();
      safeLog("Simulated password update completed securely.");
      show("success");
    });

    setup();
  </script>
</body>
</html>`;
}

async function handleApi(
  request: Request,
  path: string,
  session: Session,
): Promise<Response> {
  if (path === "/api/session" && request.method === "GET") {
    return json({ csrf: session.csrf }, 200, session);
  }

  if (request.method !== "POST") {
    return json({ message: "Not found." }, 404, session);
  }

  if (!validCsrf(request, session)) {
    return json({ message: "Your secure session has expired. Refresh the page and try again." }, 403, session);
  }

  const body = await readBody(request);
  if (!body) return json({ message: "Invalid request." }, 400, session);

  // S1/S4: Privacy-preserving reset request, validation, and session rate limiting.
  if (path === "/api/reset-request") {
    if (limited(session.requestAttempts, 3, 10 * 60 * 1000)) {
      return json(
        { message: "For your security, please wait before requesting another recovery message." },
        429,
        session,
      );
    }

    const identifier = validIdentifier(body.identifier);
    const generic =
      "If the account can be recovered, secure recovery instructions have been prepared.";

    // Invalid input gets the same privacy-preserving confirmation and never leaks account existence.
    if (!identifier || !safeEqual(identifier, MOCK_ACCOUNT_IDENTIFIER)) {
      return json({ message: generic }, 200, session);
    }

    if (activeResetKey) {
      const previous = resets.get(activeResetKey);
      if (previous) previous.used = true;
    }

    const rawToken = makeToken(32);
    const tokenDigest = digest(rawToken);
    const key = tokenDigest.toString("hex");
    resets.set(key, {
      digest: tokenDigest,
      expiresAt: Date.now() + RESET_TTL_MS,
      used: false,
    });
    activeResetKey = key;

    // Mock-only token is intentionally returned for academic testing; no identifier is returned.
    return json({ message: generic, testToken: rawToken }, 200, session);
  }

  // S4: token verification accepts URL-derived/manual codes, throttles guesses, and binds success to session.
  if (path === "/api/reset-verify") {
    if (limited(session.verifyAttempts, 5, 10 * 60 * 1000)) {
      return json(
        { message: "Too many attempts. Request a new recovery code and try again later." },
        429,
        session,
      );
    }

    const rawToken = validResetToken(body.token);
    const tokenDigest = rawToken ? digest(rawToken) : null;
    const key = tokenDigest ? tokenDigest.toString("hex") : "";
    const record = key ? resets.get(key) : undefined;

    if (
      !record ||
      !tokenDigest ||
      !safeEqual(tokenDigest, record.digest) ||
      record.used ||
      record.expiresAt <= Date.now() ||
      (record.boundSessionId && record.boundSessionId !== session.id)
    ) {
      return json(
        { message: "This recovery code is invalid, expired, or no longer available. Request a new code." },
        400,
        session,
      );
    }

    record.boundSessionId = session.id;
    session.resetKey = key;
    session.mfaComplete = false;
    return json(
      {
        message: "Recovery code verified.",
        // Mock delivery only: client logs this deterministic test code in browser console/Logs panel.
        testMfaCode: MFA_TEST_CODE,
      },
      200,
      session,
    );
  }

  // S4: MFA is required after reset-token verification and incorrect code attempts are throttled.
  if (path === "/api/mfa-verify") {
    if (!resetForSession(session)) {
      return json({ message: "Verify a valid recovery code before confirming identity." }, 403, session);
    }
    if (limited(session.mfaAttempts, 5, 10 * 60 * 1000)) {
      return json(
        { message: "Too many incorrect codes. Request a new recovery code and try again later." },
        429,
        session,
      );
    }
    const code = typeof body.code === "string" ? body.code : "";
    if (!/^[0-9]{6}$/.test(code) || !safeEqual(code, MFA_TEST_CODE)) {
      return json({ message: "The verification code is incorrect or expired." }, 400, session);
    }
    session.mfaComplete = true;
    return json({ message: "Identity confirmed." }, 200, session);
  }

  // S4: Argon2 password update requires valid reset token + completed MFA + CSRF.
  if (path === "/api/password-update") {
    const reset = resetForSession(session);
    if (!reset || !session.mfaComplete) {
      return json(
        { message: "Your recovery verification is no longer active. Start recovery again." },
        403,
        session,
      );
    }

    const problem = passwordProblem(body.password);
    if (problem) return json({ message: problem }, 400, session);

    mockPasswordHash = await Bun.password.hash(body.password as string, {
      algorithm: "argon2id",
    });
    reset.used = true;
    session.resetKey = undefined;
    session.mfaComplete = false;
    // S3/S4: Server audit contains no password, token, account ID, or patient data.
    console.log("[audit] Password recovery update completed securely.");
    return json({ message: "Password updated." }, 200, session);
  }

  return json({ message: "Not found." }, 404, session);
}

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";

try {
  // S3: This listener is TLS-only. Plain HTTP sent to this port is rejected at TLS negotiation.
  const certificate = readFileSync(certPath, "utf8");
  const privateKey = readFileSync(keyPath, "utf8");

  Bun.serve({
    port: PORT,
    hostname: "0.0.0.0",
    tls: { cert: certificate, key: privateKey },
    async fetch(request) {
      const { session } = sessionFor(request);
      const requestUrl = new URL(request.url);

      try {
        // S3: Reject a request that a trusted TLS-terminating proxy explicitly marks insecure.
        const forwardedProtocol = request.headers.get("x-forwarded-proto");
        if (forwardedProtocol && forwardedProtocol.toLowerCase() !== "https") {
          return response("HTTPS is required.", { status: 426, session });
        }

        if (requestUrl.pathname.startsWith("/api/")) {
          return await handleApi(request, requestUrl.pathname, session);
        }

        if (request.method === "GET" && requestUrl.pathname === "/") {
          const pageNonce = nonce();
          return response(htmlPage(pageNonce), {
            type: "text/html; charset=utf-8",
            session,
            nonce: pageNonce,
          });
        }

        // S3: No directory exposure, debug output, or route details.
        return response("Not found.", { status: 404, session });
      } catch {
        // S3: Safe production failure response without stack traces.
        return response("Unable to process this request.", { status: 500, session });
      }
    },
  });

  console.log(`Secure Hospital Account Recovery listening on https://localhost:${PORT}`);
} catch {
  // Do not expose file paths, key material, or stack traces.
  console.log("Secure server could not start.");
  process.exit(1);
}
