
/*
 * Password Recovery System, single-file Bun application.
 * Security requirement comments use the numbering from the supplied requirements.
 */

// [3] TLS is enabled whenever the supplied mkcert files are present. The HTTP fallback
// exists only to keep local development runnable before those certificates are installed.
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");
const tlsReady = (await certFile.exists()) && (await keyFile.exists());
const scheme = tlsReady ? "https" : "http";
const secureCookie = tlsReady;

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  resetTokenHash?: string;
  resetExpiresAt?: number;
  recoveryGrantUntil?: number;
  attempts: number[];
};

const sessions = new Map<string, Session>();
const RATE_WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 5;
const RESET_LIFETIME_MS = 10 * 60_000;
const GRANT_LIFETIME_MS = 5 * 60_000;

// [4] Passwords are never stored in plaintext; Bun uses Argon2id for this mock account.
let accountPasswordHash = await Bun.password.hash("Initial-Not-Usable-Password-42!", {
  algorithm: "argon2id",
});

const nonce = crypto.getRandomValues(new Uint8Array(18));
const cspNonce = btoa(String.fromCharCode(...nonce));

function randomValue(bytes = 32): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function parseCookies(request: Request): Record<string, string> {
  const header = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return result;
}

function getSession(request: Request): { session: Session; isNew: boolean } {
  const id = parseCookies(request).recovery_session;
  const existing = id ? sessions.get(id) : undefined;
  if (existing) return { session: existing, isNew: false };

  const session: Session = {
    id: randomValue(),
    csrf: randomValue(),
    createdAt: Date.now(),
    authenticated: false,
    attempts: [],
  };
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function sessionCookie(session: Session): string {
  // [1,3] HttpOnly, SameSite and Secure cookies limit CSRF/session theft.
  return `recovery_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800${secureCookie ? "; Secure" : ""}`;
}

function baseHeaders(): Headers {
  // [2,3] CSP blocks injected scripts; browser security headers prevent framing/sniffing.
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${cspNonce}'; style-src 'nonce-${cspNonce}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (tlsReady) headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  return headers;
}

function responseJson(data: unknown, status = 200, cookie?: string): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function responseHtml(html: string, cookie?: string): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "text/html; charset=utf-8");
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(html, { headers });
}

// [1] Every state-changing endpoint requires both same-origin requests and a per-session CSRF token.
function validSensitiveRequest(request: Request, session: Session, body: Record<string, unknown>): boolean {
  const host = request.headers.get("host") || "localhost:3000";
  const origin = request.headers.get("origin");
  const expectedOrigin = `${scheme}://${host}`;
  const csrf = request.headers.get("x-csrf-token");
  return origin === expectedOrigin && csrf === session.csrf && body.csrf === session.csrf;
}

function rateAllowed(session: Session): boolean {
  const now = Date.now();
  session.attempts = session.attempts.filter(time => now - time < RATE_WINDOW_MS);
  if (session.attempts.length >= MAX_ATTEMPTS) return false;
  session.attempts.push(now);
  return true;
}

// [2] Strict JSON parsing and allow-list validation keep untrusted input out of HTML and commands.
async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return null;
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function safeEmail(value: unknown): boolean {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(value);
}

function safeToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{30,100}$/.test(value);
}

function strongPassword(value: unknown): value is string {
  return typeof value === "string" &&
    value.length >= 14 &&
    value.length <= 128 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

function page(csrf: string): string {
  // [2] csrf is random base64url data; it is JSON encoded rather than interpolated as HTML.
  const safeCsrf = JSON.stringify(csrf);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Recovery</title>
  <style nonce="${cspNonce}">
    :root { color-scheme: light; --blue:#0a4d78; --ink:#182633; --muted:#566575; --line:#c9d5df; --soft:#eef6fa; --danger:#a22b25; --ok:#17633b; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f4f7f9; color:var(--ink); font:16px/1.5 Arial,sans-serif; }
    header { background:var(--blue); color:white; padding:22px 20px; }
    header div, main { max-width:760px; margin:auto; }
    h1 { font-size:1.45rem; margin:0; } header p { margin:3px 0 0; opacity:.92; }
    main { padding:28px 20px 40px; }
    section.card { background:white; border:1px solid var(--line); border-radius:10px; padding:24px; box-shadow:0 2px 6px #18364a12; }
    h2 { margin-top:0; font-size:1.28rem; } p { margin:10px 0; } .muted { color:var(--muted); }
    label { display:block; font-weight:bold; margin-top:16px; } input { width:100%; padding:11px; border:1px solid #8395a5; border-radius:5px; font:inherit; }
    button { margin-top:20px; padding:11px 17px; border:0; border-radius:5px; background:var(--blue); color:white; font:inherit; font-weight:bold; cursor:pointer; }
    button:hover { background:#073d60; } button.secondary { background:#607383; margin-left:8px; }
    .notice { margin:17px 0 0; padding:12px; border-radius:5px; background:var(--soft); border-left:4px solid var(--blue); }
    .error { border-left-color:var(--danger); background:#fff1ef; color:#74201c; }
    .success { border-left-color:var(--ok); background:#effaf3; color:#124c2d; }
    .safety { border-top:1px solid var(--line); margin-top:22px; padding-top:16px; font-size:.93rem; }
    #logs { margin-top:20px; background:#101b24; color:#d9edf8; border-radius:8px; padding:14px; }
    #logs h2 { font-size:1rem; margin:0 0 6px; } #log-output { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font:12px/1.45 monospace; max-height:180px; overflow:auto; }
    a { color:#075b91; } .status { font-size:.9rem; color:var(--muted); }
  </style>
</head>
<body>
  <header><div><h1>Hospital Account Recovery</h1><p>Secure access to accept updated privacy conditions</p></div></header>
  <main>
    <section class="card" aria-live="polite" id="screen"></section>
    <section id="logs" aria-live="polite"><h2>Logs (simulated delivery)</h2><pre id="log-output">Secure recovery flow ready.</pre></section>
  </main>
  <script nonce="${cspNonce}">
    "use strict";
    // [2] The client only writes controlled templates with innerHTML; all dynamic text uses textContent.
    const CSRF = ${safeCsrf};
    const screen = document.getElementById("screen");
    const logOutput = document.getElementById("log-output");

    function log(message) {
      console.log(message); // Required simulated browser-side delivery/verification log.
      logOutput.textContent += "\\n" + message;
      logOutput.scrollTop = logOutput.scrollHeight;
    }

    function notice(text, type) {
      const box = document.createElement("p");
      box.className = "notice " + (type || "");
      box.textContent = text;
      screen.prepend(box);
    }

    async function api(path, payload) {
      const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
        body: JSON.stringify(Object.assign({}, payload, { csrf: CSRF }))
      });
      const result = await response.json().catch(() => ({ ok:false, message:"A secure request could not be processed." }));
      if (!response.ok || !result.ok) throw new Error(result.message || "Request was not accepted.");
      return result;
    }

    function safety() {
      return '<aside class="safety"><strong>Stay safe.</strong> Hospital staff will never ask for your password or recovery code by email or telephone. Check that this page is your local hospital portal before entering a code.</aside>';
    }

    function recoveryView() {
      screen.innerHTML = '<h2>Reset your password</h2><p class="muted">Enter the email address registered for your healthcare account. For privacy, the response is the same whether or not an account exists.</p><form id="recovery-form"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" maxlength="254" required><button type="submit">Send recovery verification</button></form>' + safety();
      document.getElementById("recovery-form").addEventListener("submit", async event => {
        event.preventDefault();
        const email = document.getElementById("email").value;
        try {
          const result = await api("/api/request-reset", { email });
          // [4] Test-only deterministic delivery is deliberately visible only in this browser demo.
          log("SIMULATED DELIVERY — recovery code: " + result.testToken);
          log("SIMULATED MFA — verification code: " + result.testMfaCode);
          location.hash = "#verify?code=" + encodeURIComponent(result.testToken);
        } catch (error) { notice(error.message, "error"); }
      });
    }

    function verifyView() {
      const params = new URLSearchParams(location.hash.split("?")[1] || "");
      // [5] URL handling accepts only a local hash value; no redirect or outgoing URL is ever followed.
      const prefill = /^[A-Za-z0-9_-]{30,100}$/.test(params.get("code") || "") ? params.get("code") : "";
      screen.innerHTML = '<h2>Verify recovery</h2><p class="muted">Use the code from the recovery message. You may paste it manually if you did not use the verification link.</p><form id="verify-form"><label for="token">Recovery code</label><input id="token" autocomplete="one-time-code" maxlength="100" required><label for="mfa">Six-digit verification code</label><input id="mfa" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button type="submit">Verify and continue</button><button class="secondary" type="button" id="back">Start over</button></form>' + safety();
      document.getElementById("token").value = prefill;
      document.getElementById("verify-form").addEventListener("submit", async event => {
        event.preventDefault();
        try {
          await api("/api/verify-reset", { token: document.getElementById("token").value, mfaCode: document.getElementById("mfa").value });
          log("SIMULATED VERIFICATION — recovery code and MFA accepted.");
          location.hash = "#new-password";
        } catch (error) { notice(error.message, "error"); }
      });
      document.getElementById("back").addEventListener("click", () => { location.hash = "#recover"; });
    }

    function passwordView() {
      screen.innerHTML = '<h2>Create a new password</h2><p class="muted">Use at least 14 characters, including uppercase, lowercase, a number, and a symbol.</p><form id="password-form"><label for="password">New password</label><input id="password" type="password" autocomplete="new-password" maxlength="128" required><label for="confirm">Confirm new password</label><input id="confirm" type="password" autocomplete="new-password" maxlength="128" required><button type="submit">Save secure password</button></form>' + safety();
      document.getElementById("password-form").addEventListener("submit", async event => {
        event.preventDefault();
        const password = document.getElementById("password").value;
        if (password !== document.getElementById("confirm").value) return notice("The passwords do not match.", "error");
        try {
          await api("/api/set-password", { password });
          log("SIMULATED AUTHENTICATION — password reset completed and secure session established.");
          location.hash = "#portal";
        } catch (error) { notice(error.message, "error"); }
      });
    }

    function portalView() {
      screen.innerHTML = '<h2>Privacy conditions</h2><p>You have securely recovered access. Please accept the updated privacy conditions so hospital authorities may continue with appointment booking.</p><p class="status" id="accept-status">Review the statement before confirming.</p><button id="accept">Accept updated privacy conditions</button>' + safety();
      document.getElementById("accept").addEventListener("click", async () => {
        try {
          await api("/api/accept-privacy", {});
          document.getElementById("accept-status").textContent = "Accepted securely. Hospital appointment booking may proceed.";
          log("SIMULATED CONFIRMATION — updated privacy conditions accepted.");
        } catch (error) { notice(error.message, "error"); }
      });
    }

    function render() {
      const route = location.hash.split("?")[0] || "#recover";
      if (route === "#verify") verifyView();
      else if (route === "#new-password") passwordView();
      else if (route === "#portal") portalView();
      else recoveryView();
    }
    window.addEventListener("hashchange", render);
    render();
  </script>
</body>
</html>`;
}

async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const { session, isNew } = getSession(request);
  const cookie = isNew ? sessionCookie(session) : undefined;

  if (request.method === "GET" && url.pathname === "/") return responseHtml(page(session.csrf), cookie);
  if (request.method !== "POST" || !url.pathname.startsWith("/api/")) {
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  }

  const body = await readJson(request);
  if (!body) return responseJson({ ok: false, message: "Invalid request format." }, 400, cookie);
  if (!validSensitiveRequest(request, session, body)) {
    return responseJson({ ok: false, message: "Security validation failed. Refresh and try again." }, 403, cookie);
  }
  if (!rateAllowed(session)) {
    return responseJson({ ok: false, message: "Too many attempts. Please wait one minute before trying again." }, 429, cookie);
  }

  if (url.pathname === "/api/request-reset") {
    if (!safeEmail(body.email)) return responseJson({ ok: false, message: "Enter a valid email address." }, 400, cookie);

    // [3,4] A cryptographically random, hashed-at-rest, short-lived recovery token is created.
    const token = randomValue(32);
    session.resetTokenHash = await sha256(token);
    session.resetExpiresAt = Date.now() + RESET_LIFETIME_MS;
    session.recoveryGrantUntil = undefined;
    // No account existence or patient identifier is disclosed here. [1,3,4]
    return responseJson({
      ok: true,
      message: "If an eligible account exists, verification instructions have been sent.",
      testToken: token,
      testMfaCode: "246810",
    }, 200, cookie);
  }

  if (url.pathname === "/api/verify-reset") {
    if (!safeToken(body.token) || body.mfaCode !== "246810") {
      return responseJson({ ok: false, message: "The recovery or verification code is invalid." }, 400, cookie);
    }
    const candidateHash = await sha256(body.token);
    if (!session.resetTokenHash || !session.resetExpiresAt || Date.now() > session.resetExpiresAt || candidateHash !== session.resetTokenHash) {
      return responseJson({ ok: false, message: "This recovery code is invalid or has expired." }, 400, cookie);
    }
    // [3,4] Token is consumed once; only a short session-bound grant can set the password.
    session.resetTokenHash = undefined;
    session.resetExpiresAt = undefined;
    session.recoveryGrantUntil = Date.now() + GRANT_LIFETIME_MS;
    return responseJson({ ok: true, message: "Recovery verified." }, 200, cookie);
  }

  if (url.pathname === "/api/set-password") {
    if (!session.recoveryGrantUntil || Date.now() > session.recoveryGrantUntil) {
      return responseJson({ ok: false, message: "Your verified recovery session expired. Start again." }, 403, cookie);
    }
    if (!strongPassword(body.password)) {
      return responseJson({ ok: false, message: "Password must be 14+ characters with uppercase, lowercase, number, and symbol." }, 400, cookie);
    }
    // [4] Argon2id password hashing occurs before the plaintext leaves this handler scope.
    accountPasswordHash = await Bun.password.hash(body.password, { algorithm: "argon2id" });
    session.recoveryGrantUntil = undefined;
    session.authenticated = true;
    return responseJson({ ok: true, message: "Password updated." }, 200, cookie);
  }

  if (url.pathname === "/api/accept-privacy") {
    // [1] This sensitive action is session-authorized, not selected by a user-controlled ID.
    if (!session.authenticated) return responseJson({ ok: false, message: "Authentication is required." }, 403, cookie);
    return responseJson({ ok: true, message: "Privacy conditions accepted." }, 200, cookie);
  }

  return responseJson({ ok: false, message: "Not found." }, 404, cookie);
}

const serverOptions: Record<string, unknown> = {
  port: 3000,
  hostname: "localhost",
  fetch: handler,
};
if (tlsReady) serverOptions.tls = { cert: certFile, key: keyFile };

Bun.serve(serverOptions as Parameters<typeof Bun.serve>[0]);
console.log(`Hospital recovery server listening at ${scheme}://localhost:3000`);
if (!tlsReady) console.log("Development fallback: add certs/cert.pem and certs/key.pem to enable HTTPS.");
