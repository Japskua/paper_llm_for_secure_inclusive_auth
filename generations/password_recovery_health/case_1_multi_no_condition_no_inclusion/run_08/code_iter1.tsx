
import { existsSync } from "node:fs";

/*
 * Password Recovery System
 * Single-file Bun HTTPS server and vanilla JavaScript SPA.
 *
 * Security requirement mapping:
 * 1: Session-bound CSRF tokens, strict session cookie, access checks.
 * 2: Client only writes dynamic data with textContent; server never reflects input.
 * 3: HTTPS, HSTS, CSP and secure response headers; random expiring reset tokens.
 * 4: Argon2 hashing, throttling, strong password checks, mock MFA.
 * 5: No outgoing URLs, no redirects based on input, anti-phishing guidance.
 */

const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3001);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3000);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryRequests: number[];
  flowId: string | null;
  resetComplete: boolean;
  mfaFailures: number;
  authenticated: boolean;
  privacyAccepted: boolean;
};

type RecoveryRecord = {
  token: string;
  flowId: string;
  expiresAt: number;
  used: boolean;
  failedAttempts: number;
  blockedUntil: number;
};

const sessions = new Map<string, Session>();
const recoveries = new Map<string, RecoveryRecord>();

// Requirement 4: only an Argon2 hash is retained after a successful reset.
let passwordHash = "";
let passwordHashReady: Promise<void> | null = null;

function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") || "";
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index > -1 && part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return null;
}

function getSession(request: Request): Session | null {
  const id = cookieValue(request, "hospital_recovery_session");
  if (!id) return null;
  const session = sessions.get(id) || null;
  if (session && Date.now() - session.createdAt > 8 * 60 * 60 * 1000) {
    sessions.delete(id);
    return null;
  }
  return session;
}

function makeSession(): Session {
  const session: Session = {
    id: randomValue(),
    csrf: randomValue(),
    createdAt: Date.now(),
    recoveryRequests: [],
    flowId: null,
    resetComplete: false,
    mfaFailures: 0,
    authenticated: false,
    privacyAccepted: false,
  };
  sessions.set(session.id, session);
  return session;
}

function commonHeaders(nonce = ""): Headers {
  const headers = new Headers();
  // Requirement 3: secure transport and browser hardening headers.
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`,
  );
  return headers;
}

function json(body: Record<string, unknown>, status = 200): Response {
  const headers = commonHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function cleanOldState(): void {
  const now = Date.now();
  for (const [token, record] of recoveries) {
    if (record.expiresAt < now - 60 * 60 * 1000) recoveries.delete(token);
  }
  for (const [id, session] of sessions) {
    if (session.createdAt < now - 8 * 60 * 60 * 1000) sessions.delete(id);
  }
}

// Requirement 1: all state-changing routes require current session + matching CSRF token.
function authorizeStateChange(request: Request): { session: Session } | { error: Response } {
  const session = getSession(request);
  if (!session) return { error: json({ error: "Your secure session has expired. Please reload the page." }, 401) };

  const token = request.headers.get("x-csrf-token") || "";
  if (!token || token !== session.csrf) {
    return { error: json({ error: "This request could not be verified. Please reload and try again." }, 403) };
  }

  const origin = request.headers.get("origin");
  if (origin) {
    const expectedOrigin = new URL(request.url).origin;
    if (origin !== expectedOrigin) {
      return { error: json({ error: "This request could not be verified. Please reload and try again." }, 403) };
    }
  }
  return { session };
}

async function requestData(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  try {
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

function passwordProblem(password: string): string | null {
  if (password.length < 12) return "Use at least 12 characters.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/[0-9]/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include a symbol.";
  return null;
}

const page = (csrf: string, nonce: string) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --navy:#12314a; --blue:#146c94; --pale:#edf6f9; --line:#c9d8df; --danger:#a32638; --ok:#17663d; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f4f7f8; color:#17242c; font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
    header { background:var(--navy); color:white; padding:1.2rem 1rem; }
    header div, main { max-width:760px; margin:auto; }
    header h1 { margin:0; font-size:1.35rem; }
    header p { margin:.18rem 0 0; color:#d7edf5; font-size:.94rem; }
    main { padding:1.5rem 1rem 3rem; }
    .card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.4rem; box-shadow:0 1px 3px #12314a12; }
    h2 { margin-top:0; color:var(--navy); font-size:1.35rem; }
    h3 { font-size:1rem; margin-bottom:.35rem; }
    label { display:block; font-weight:bold; margin:1rem 0 .32rem; }
    input { width:100%; padding:.72rem; border:1px solid #78909c; border-radius:5px; font-size:1rem; }
    input:focus { outline:3px solid #a9d9ea; outline-offset:1px; }
    button { margin-top:1.1rem; padding:.7rem 1rem; font-size:1rem; border:0; border-radius:5px; background:var(--blue); color:white; cursor:pointer; }
    button:hover { background:#0d5679; }
    button.secondary { background:#e7f0f3; color:#173d50; border:1px solid #9eb8c2; margin-left:.45rem; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    .notice { background:var(--pale); border-left:4px solid var(--blue); padding:.8rem; margin:1rem 0; }
    .warning { background:#fff7e7; border-left-color:#a66a00; }
    .status { margin:1rem 0; padding:.75rem; border-radius:5px; background:#eef6f0; color:var(--ok); }
    .error { background:#fff0f1; color:var(--danger); }
    .hidden { display:none !important; }
    .small { font-size:.9rem; color:#43545c; }
    .actions { display:flex; flex-wrap:wrap; align-items:center; }
    .actions button { margin-right:.45rem; }
    .check { display:flex; gap:.6rem; align-items:flex-start; margin-top:1rem; }
    .check input { width:auto; margin-top:.3rem; }
    #logs { margin-top:1.3rem; background:#10212c; color:#d9f5e6; border-radius:8px; padding:1rem; }
    #logs h2 { color:white; font-size:1rem; margin:0 0 .4rem; }
    #log-output { margin:0; max-height:180px; overflow:auto; white-space:pre-wrap; font: .82rem ui-monospace,SFMono-Regular,Consolas,monospace; }
    a { color:#075f87; }
  </style>
</head>
<body>
  <header><div><h1>Hospital Account Recovery</h1><p>Secure access for privacy conditions and appointment support</p></div></header>
  <main>
    <section id="screen-request" class="card" aria-labelledby="request-title">
      <h2 id="request-title">Reset your password</h2>
      <p>Enter the email address used for your healthcare account. We will provide the same response whether or not it is registered.</p>
      <form id="recovery-form" novalidate>
        <label for="email">Email address</label>
        <input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
        <div id="request-message" class="status hidden" role="status"></div>
        <div class="actions"><button type="submit">Request reset instructions</button><button type="button" class="secondary" data-route="verify">Enter a reset token</button></div>
      </form>
      <aside class="notice warning"><h3>Stay safe</h3><p class="small">Hospital staff will never ask for your password or MFA code by email or phone. Use this page directly and do not follow unexpected authentication links.</p></aside>
    </section>

    <section id="screen-verify" class="card hidden" aria-labelledby="verify-title">
      <h2 id="verify-title">Verify reset token</h2>
      <p>Paste the token from your simulated recovery message, or use the simulated link button shown after making a request.</p>
      <form id="verify-form" novalidate>
        <label for="token">Reset token</label>
        <input id="token" name="token" autocomplete="one-time-code" spellcheck="false" maxlength="128" required>
        <div id="verify-message" class="status hidden" role="status"></div>
        <div class="actions"><button type="submit">Verify token</button><button type="button" class="secondary" data-route="request">Back</button></div>
      </form>
    </section>

    <section id="screen-reset" class="card hidden" aria-labelledby="reset-title">
      <h2 id="reset-title">Choose a new password</h2>
      <p class="small">Use 12 or more characters with uppercase, lowercase, number, and symbol.</p>
      <form id="reset-form" novalidate>
        <label for="password">New password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" maxlength="256" required>
        <label for="confirm-password">Confirm new password</label>
        <input id="confirm-password" name="confirm-password" type="password" autocomplete="new-password" maxlength="256" required>
        <div id="reset-message" class="status hidden" role="status"></div>
        <button type="submit">Save password and continue</button>
      </form>
    </section>

    <section id="screen-mfa" class="card hidden" aria-labelledby="mfa-title">
      <h2 id="mfa-title">One-time verification</h2>
      <p>For this secure demonstration, a six-digit verification code was delivered to the visible Logs panel and browser console.</p>
      <form id="mfa-form" novalidate>
        <label for="mfa-code">Verification code</label>
        <input id="mfa-code" name="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required>
        <div id="mfa-message" class="status hidden" role="status"></div>
        <button type="submit">Verify and sign in</button>
      </form>
    </section>

    <section id="screen-privacy" class="card hidden" aria-labelledby="privacy-title">
      <h2 id="privacy-title">Updated privacy conditions</h2>
      <p>Please review and accept the updated privacy conditions so hospital authorities can continue appointment support.</p>
      <div class="notice"><p><strong>Privacy summary:</strong> Your healthcare information is used only for care, appointment coordination, and legally required hospital administration. Keep your account credentials private.</p></div>
      <form id="privacy-form">
        <label class="check" for="privacy-check"><input id="privacy-check" type="checkbox" required><span>I have read and accept the updated privacy conditions.</span></label>
        <div id="privacy-message" class="status hidden" role="status"></div>
        <button type="submit">Accept conditions</button>
      </form>
    </section>

    <section id="screen-complete" class="card hidden" aria-labelledby="complete-title">
      <h2 id="complete-title">Conditions accepted</h2>
      <p>Your password reset and privacy-condition acceptance have been recorded. Hospital appointment support can now continue.</p>
      <button type="button" data-route="request">Return to recovery start</button>
    </section>

    <section id="logs" aria-labelledby="logs-title">
      <h2 id="logs-title">Logs</h2>
      <pre id="log-output" aria-live="polite">Secure recovery page ready.</pre>
    </section>
  </main>

  <script nonce="${nonce}">
    (() => {
      "use strict";
      const csrf = ${JSON.stringify(csrf)};
      const routes = ["request", "verify", "reset", "mfa", "privacy", "complete"];
      const logs = document.getElementById("log-output");
      let deliveredToken = "";

      // Requirement 2: all runtime values are inserted with textContent, never innerHTML.
      function log(message) {
        console.log(message);
        logs.textContent += "\\n" + message;
        logs.scrollTop = logs.scrollHeight;
      }
      function showMessage(id, message, isError) {
        const box = document.getElementById(id);
        box.textContent = message;
        box.classList.remove("hidden");
        box.classList.toggle("error", Boolean(isError));
      }
      function clearMessage(id) {
        const box = document.getElementById(id);
        box.textContent = "";
        box.classList.add("hidden");
        box.classList.remove("error");
      }
      function routeName() {
        const candidate = location.hash.replace(/^#/, "");
        return routes.includes(candidate) ? candidate : "request";
      }
      function render() {
        const active = routeName();
        routes.forEach((name) => document.getElementById("screen-" + name).classList.toggle("hidden", name !== active));
      }
      function go(name) {
        if (routes.includes(name)) location.hash = name;
      }
      async function api(path, body) {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify(body)
        });
        const data = await response.json().catch(() => ({ error: "The secure service returned an invalid response." }));
        if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "The request could not be completed.");
        return data;
      }

      document.querySelectorAll("[data-route]").forEach((button) => {
        button.addEventListener("click", () => go(button.getAttribute("data-route")));
      });
      addEventListener("hashchange", render);

      document.getElementById("recovery-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage("request-message");
        const email = document.getElementById("email").value.trim();
        if (!email || !document.getElementById("email").checkValidity()) {
          showMessage("request-message", "Enter a valid email address.", true);
          return;
        }
        try {
          const data = await api("/api/recovery", { email });
          deliveredToken = String(data.mockToken || "");
          showMessage("request-message", String(data.message || "If an account can be recovered, instructions have been sent."), false);
          log("[Mock delivery] Reset token: " + deliveredToken);
          log("[Mock delivery] Secure simulated link: #verify (token can also be pasted manually)");
          const useButton = document.createElement("button");
          useButton.type = "button";
          useButton.className = "secondary";
          useButton.textContent = "Use simulated recovery link";
          useButton.addEventListener("click", () => {
            document.getElementById("token").value = deliveredToken;
            go("verify");
          });
          const existing = document.getElementById("use-link-button");
          if (existing) existing.remove();
          useButton.id = "use-link-button";
          document.getElementById("recovery-form").appendChild(useButton);
        } catch (error) {
          showMessage("request-message", error.message, true);
        }
      });

      document.getElementById("verify-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage("verify-message");
        const token = document.getElementById("token").value.trim();
        if (!/^[a-f0-9]{32,128}$/i.test(token)) {
          showMessage("verify-message", "Enter the reset token exactly as provided.", true);
          return;
        }
        try {
          await api("/api/verify", { token });
          showMessage("verify-message", "Token verified.", false);
          go("reset");
        } catch (error) {
          showMessage("verify-message", error.message, true);
        }
      });

      document.getElementById("reset-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage("reset-message");
        const password = document.getElementById("password").value;
        const confirmation = document.getElementById("confirm-password").value;
        if (password !== confirmation) {
          showMessage("reset-message", "The password confirmation does not match.", true);
          return;
        }
        try {
          const data = await api("/api/reset", { password, confirmation });
          log("[Mock MFA delivery] Verification code: " + String(data.mockMfaCode || ""));
          go("mfa");
        } catch (error) {
          showMessage("reset-message", error.message, true);
        }
      });

      document.getElementById("mfa-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage("mfa-message");
        const code = document.getElementById("mfa-code").value.trim();
        if (!/^[0-9]{6}$/.test(code)) {
          showMessage("mfa-message", "Enter the six-digit verification code.", true);
          return;
        }
        try {
          await api("/api/mfa", { code });
          go("privacy");
        } catch (error) {
          showMessage("mfa-message", error.message, true);
        }
      });

      document.getElementById("privacy-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        clearMessage("privacy-message");
        if (!document.getElementById("privacy-check").checked) {
          showMessage("privacy-message", "Please confirm that you accept the conditions.", true);
          return;
        }
        try {
          await api("/api/privacy", { accepted: true });
          go("complete");
        } catch (error) {
          showMessage("privacy-message", error.message, true);
        }
      });

      render();
    })();
  </script>
</body>
</html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  cleanOldState();
  const auth = authorizeStateChange(request);
  if ("error" in auth) return auth.error;
  const session = auth.session;
  const body = await requestData(request);
  if (!body) return json({ error: "The request format was not accepted." }, 400);

  if (pathname === "/api/recovery") {
    const email = typeof body.email === "string" ? body.email.trim() : "";
    if (!email || email.length > 254) return json({ error: "Enter a valid email address." }, 400);

    const now = Date.now();
    session.recoveryRequests = session.recoveryRequests.filter((time) => now - time < 10 * 60 * 1000);
    if (session.recoveryRequests.length >= 3) {
      return json({ error: "Too many recovery requests. Please wait before trying again." }, 429);
    }
    session.recoveryRequests.push(now);

    // Requirement 3/4: random, opaque, short-lived token. No account data appears in output.
    const token = randomValue(32);
    recoveries.set(token, {
      token,
      flowId: randomValue(24),
      expiresAt: now + 15 * 60 * 1000,
      used: false,
      failedAttempts: 0,
      blockedUntil: 0,
    });

    return json({
      message: "If an account can be recovered, reset instructions have been prepared.",
      mockToken: token,
    });
  }

  if (pathname === "/api/verify") {
    const token = typeof body.token === "string" ? body.token : "";
    const record = recoveries.get(token);
    const now = Date.now();

    if (!record || record.expiresAt <= now || record.used || record.blockedUntil > now) {
      return json({ error: "This reset token is invalid, expired, or unavailable. Request a new one if needed." }, 400);
    }
    if (!/^[a-f0-9]{64}$/i.test(token)) {
      record.failedAttempts++;
      if (record.failedAttempts >= 5) record.blockedUntil = now + 10 * 60 * 1000;
      return json({ error: "This reset token is invalid, expired, or unavailable. Request a new one if needed." }, 400);
    }

    // Requirement 3: token is single-use immediately after successful verification.
    record.used = true;
    session.flowId = record.flowId;
    session.resetComplete = false;
    session.mfaFailures = 0;
    return json({ ok: true });
  }

  if (pathname === "/api/reset") {
    if (!session.flowId || session.resetComplete) {
      return json({ error: "Verify a valid reset token before choosing a new password." }, 403);
    }
    const password = typeof body.password === "string" ? body.password : "";
    const confirmation = typeof body.confirmation === "string" ? body.confirmation : "";
    if (password !== confirmation) return json({ error: "The password confirmation does not match." }, 400);
    const problem = passwordProblem(password);
    if (problem) return json({ error: problem }, 400);

    // Requirement 4: Bun's Argon2id implementation; password is never stored plaintext.
    if (!passwordHashReady) passwordHashReady = Bun.password.hash("initial-placeholder-value", { algorithm: "argon2id" }).then((hash) => { passwordHash = hash; });
    await passwordHashReady;
    passwordHash = await Bun.password.hash(password, { algorithm: "argon2id" });
    session.resetComplete = true;
    return json({ ok: true, mockMfaCode: "482916" });
  }

  if (pathname === "/api/mfa") {
    if (!session.flowId || !session.resetComplete || session.authenticated) {
      return json({ error: "A verified password reset is required before one-time verification." }, 403);
    }
    if (session.mfaFailures >= 5) {
      return json({ error: "Too many incorrect codes. Start a new recovery request." }, 429);
    }
    const code = typeof body.code === "string" ? body.code : "";
    // Requirement 4: deterministic mock MFA code remains valid during this simulated flow.
    if (code !== "482916") {
      session.mfaFailures++;
      return json({ error: "The verification code is not correct. Please try again." }, 400);
    }
    session.authenticated = true;
    return json({ ok: true });
  }

  if (pathname === "/api/privacy") {
    if (!session.authenticated) return json({ error: "Sign in securely before accepting privacy conditions." }, 403);
    if (body.accepted !== true) return json({ error: "Privacy-condition acceptance is required." }, 400);
    // Requirement 1: no user/patient identifier is accepted; current authenticated session is authoritative.
    session.privacyAccepted = true;
    return json({ ok: true });
  }

  return json({ error: "Not found." }, 404);
}

async function httpsFetch(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") {
      cleanOldState();
      let session = getSession(request);
      let created = false;
      if (!session) {
        session = makeSession();
        created = true;
      }
      const nonce = randomValue(16);
      const headers = commonHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      if (created) {
        // Requirement 1/3: session cookie cannot be read by script or sent cross-site.
        headers.append(
          "Set-Cookie",
          `hospital_recovery_session=${encodeURIComponent(session.id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`,
        );
      }
      return new Response(page(session.csrf, nonce), { status: 200, headers });
    }

    if (request.method === "POST" && [
      "/api/recovery",
      "/api/verify",
      "/api/reset",
      "/api/mfa",
      "/api/privacy",
    ].includes(url.pathname)) {
      return handleApi(request, url.pathname);
    }

    return json({ error: "Not found." }, 404);
  } catch {
    // Requirement 3: do not expose stack traces or debug details.
    return json({ error: "The request could not be completed." }, 500);
  }
}

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

// Requirement 3: HTTPS server uses the supplied mkcert certificate/key.
Bun.serve({
  port: HTTPS_PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file(CERT_PATH),
    key: Bun.file(KEY_PATH),
  },
  fetch: httpsFetch,
});

// Requirement 3: plaintext HTTP has no application content and only redirects to fixed HTTPS origin.
Bun.serve({
  port: HTTP_PORT,
  hostname: "0.0.0.0",
  fetch(request) {
    const url = new URL(request.url);
    const headers = commonHeaders();
    headers.set("Location", `https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`);
    return new Response(null, { status: 308, headers });
  },
});

console.log(`Hospital recovery HTTPS server listening at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirect listener active at http://localhost:${HTTP_PORT}`);
