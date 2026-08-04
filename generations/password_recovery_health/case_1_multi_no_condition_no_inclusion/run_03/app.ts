
const port = Number(Bun.env.PORT || 3000);
const hostname = "localhost";

type ResetRecord = {
  digest: string;
  expiresAt: number;
  tokenConsumed: boolean;
  verified: boolean;
  passwordCompleted: boolean;
};

type MfaRecord = {
  code: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
};

type Session = {
  csrf: string;
  expiresAt: number;
  recoveryAttempts: number;
  recoveryWindowStart: number;
  passwordAttempts: number;
  passwordWindowStart: number;
  reset?: ResetRecord;
  mfa?: MfaRecord;
  mfaVerified: boolean;
  passwordUpdated: boolean;
  privacyAccepted: boolean;
  passwordHash?: string;
};

const sessions = new Map<string, Session>();
const SESSION_TTL = 30 * 60 * 1000;
const RESET_TTL = 10 * 60 * 1000;
const MFA_TTL = 5 * 60 * 1000;
const THROTTLE_WINDOW = 10 * 60 * 1000;

function randomToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function digest(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (value) => value.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie") || "";
  const item = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return item ? item.slice(name.length + 1) : undefined;
}

function makeSession(): { id: string; session: Session } {
  const id = randomToken(32);
  const now = Date.now();
  const session: Session = {
    csrf: randomToken(32),
    expiresAt: now + SESSION_TTL,
    recoveryAttempts: 0,
    recoveryWindowStart: now,
    passwordAttempts: 0,
    passwordWindowStart: now,
    mfaVerified: false,
    passwordUpdated: false,
    privacyAccepted: false,
  };
  sessions.set(id, session);
  return { id, session };
}

function getSession(request: Request): Session | undefined {
  const id = cookieValue(request, "__Host-recovery_session");
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(id);
    return undefined;
  }
  session.expiresAt = Date.now() + SESSION_TTL;
  return session;
}

/* Security requirements 1 & 3: headers, no-store auth pages, HTTPS-only session cookie. */
function securityHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce || "none"}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Pragma", "no-cache");
  return headers;
}

function htmlResponse(html: string, sessionId: string): Response {
  const nonce = randomToken(16);
  const headers = securityHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set(
    "Set-Cookie",
    `__Host-recovery_session=${sessionId}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`
  );
  return new Response(html.replace("{{NONCE}}", nonce), { headers });
}

function jsonResponse(payload: Record<string, unknown>, status = 200): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(payload), { status, headers });
}

function genericError(status = 400): Response {
  return jsonResponse({ ok: false, message: "We could not complete that request. Please try again." }, status);
}

/* Security requirement 1: every changing endpoint needs same-origin request + session-specific CSRF. */
function validCsrf(request: Request, session: Session, body: Record<string, unknown>): boolean {
  const origin = request.headers.get("origin");
  try {
    const originUrl = new URL(origin || "");
    const requestUrl = new URL(request.url);
    if (originUrl.protocol !== "https:" || originUrl.host !== requestUrl.host) return false;
  } catch {
    return false;
  }
  const submitted = typeof body.csrf === "string" ? body.csrf : "";
  return submitted.length === session.csrf.length && constantTimeEqual(submitted, session.csrf);
}

function tooMany(
  session: Session,
  countKey: "recoveryAttempts" | "passwordAttempts",
  windowKey: "recoveryWindowStart" | "passwordWindowStart",
  maximum: number
): boolean {
  const now = Date.now();
  if (now - session[windowKey] > THROTTLE_WINDOW) {
    session[windowKey] = now;
    session[countKey] = 0;
  }
  session[countKey]++;
  return session[countKey] > maximum;
}

/* Security requirement 4: documented password policy, checked again on server. */
function passwordPolicy(password: string): string | null {
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/[0-9]/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9\s]/.test(password)) return "Include a symbol.";
  if (/\s/.test(password)) return "Do not use spaces.";
  if (/password|qwerty|letmein|hospital/i.test(password)) return "Choose a less predictable password.";
  return null;
}

const page = (csrf: string) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style>
    :root { color-scheme: light; --blue:#075a9c; --navy:#102a43; --line:#c9d5df; --bg:#f3f7fa; --danger:#9a1f18; --ok:#176b3a; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:#172b3a; font:17px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    header { background:var(--navy); color:white; padding:1.2rem; border-bottom:5px solid #32a3dc; }
    header div, main { max-width:760px; margin:auto; }
    header h1 { margin:0; font-size:1.45rem; }
    header p { margin:.2rem 0 0; font-size:.95rem; }
    main { padding:1.5rem 1rem 3rem; }
    section, aside { background:white; border:1px solid var(--line); border-radius:8px; padding:1.3rem; margin-bottom:1rem; box-shadow:0 1px 2px #102a4312; }
    h2 { margin-top:0; color:var(--navy); font-size:1.35rem; }
    label { display:block; font-weight:650; margin:.85rem 0 .25rem; }
    input { width:100%; padding:.7rem; border:1px solid #71869a; border-radius:4px; font:inherit; }
    input:focus { outline:3px solid #86c8ee; outline-offset:1px; }
    button, .button-link { margin-top:1rem; padding:.7rem 1rem; border:0; border-radius:4px; background:var(--blue); color:#fff; font:inherit; font-weight:700; cursor:pointer; text-decoration:none; display:inline-block; }
    button:hover, .button-link:hover { background:#034676; }
    button:disabled { opacity:.6; cursor:wait; }
    .hidden { display:none; }
    .notice { border-left:4px solid #2784bb; background:#edf8ff; padding:.8rem; }
    .error { color:var(--danger); font-weight:650; min-height:1.5em; }
    .success { color:var(--ok); font-weight:700; }
    .small { font-size:.92rem; }
    ul { padding-left:1.25rem; }
    code { overflow-wrap:anywhere; background:#eef2f4; padding:.1rem .25rem; }
    #logs { background:#0e1b26; color:#d7f2df; border-color:#0e1b26; }
    #logs h2 { color:white; }
    #logOutput { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; }
    .test-token { border:1px dashed #2784bb; padding:.7rem; margin-top:1rem; background:#f4fbff; }
  </style>
</head>
<body>
  <header><div><h1>Hospital account recovery</h1><p>Secure recovery and privacy confirmation</p></div></header>
  <main>
    <section aria-labelledby="recovery-title" id="recoveryStage">
      <h2 id="recovery-title">Recover your account</h2>
      <p>Enter the email address or account reference you normally use. For privacy, we always show the same response.</p>
      <form id="recoveryForm" novalidate>
        <label for="account">Email address or account reference</label>
        <input id="account" name="account" autocomplete="username" maxlength="160" required>
        <button type="submit">Send recovery instructions</button>
      </form>
      <p class="error" id="recoveryError" role="alert"></p>
    </section>

    <section aria-labelledby="token-title" id="tokenStage" class="hidden">
      <h2 id="token-title">Verify recovery code</h2>
      <p id="tokenMessage" class="notice">If an eligible account exists, recovery instructions have been prepared.</p>
      <p class="small">For this safe demonstration, the simulated delivery code is shown below and logged in your browser console. In a real service, never share a recovery code with anyone.</p>
      <div class="test-token"><strong>Test recovery code:</strong> <code id="testToken"></code><br><a id="recoveryLink" href="#token">Use the recovery link</a></div>
      <form id="tokenForm" novalidate>
        <label for="token">Recovery code</label>
        <input id="token" name="token" autocomplete="one-time-code" maxlength="128" required>
        <button type="submit">Verify recovery code</button>
      </form>
      <p class="error" id="tokenError" role="alert"></p>
    </section>

    <section aria-labelledby="mfa-title" id="mfaStage" class="hidden">
      <h2 id="mfa-title">Confirm with a security code</h2>
      <p>A second verification code has been sent by the demonstration delivery channel. It is visible in the Logs panel and browser console for testing.</p>
      <form id="mfaForm" novalidate>
        <label for="mfa">Security code</label>
        <input id="mfa" name="mfa" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required>
        <button type="submit">Confirm security code</button>
      </form>
      <p class="error" id="mfaError" role="alert"></p>
    </section>

    <section aria-labelledby="password-title" id="passwordStage" class="hidden">
      <h2 id="password-title">Create a new password</h2>
      <p class="notice">Use 12–128 characters with uppercase, lowercase, number, and symbol. Do not use spaces or common words such as “password”.</p>
      <form id="passwordForm" novalidate>
        <label for="password">New password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" maxlength="128" required>
        <label for="confirmPassword">Confirm new password</label>
        <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required>
        <button type="submit">Save new password</button>
      </form>
      <p class="error" id="passwordError" role="alert"></p>
    </section>

    <section aria-labelledby="privacy-title" id="privacyStage" class="hidden">
      <h2 id="privacy-title">Updated privacy conditions</h2>
      <p>Please confirm that you have reviewed the updated privacy conditions so hospital authorities can continue with appointment booking.</p>
      <ul>
        <li>Your health account is only accessed after secure verification.</li>
        <li>Never send passwords or security codes by email, text, or phone.</li>
        <li>Check that this page is served from the hospital’s secure address before entering credentials.</li>
      </ul>
      <form id="privacyForm">
        <label><input id="privacyCheck" type="checkbox" required> I have reviewed and accept the updated privacy conditions.</label>
        <button type="submit">Accept conditions</button>
      </form>
      <p class="error" id="privacyError" role="alert"></p>
    </section>

    <section aria-labelledby="success-title" id="successStage" class="hidden">
      <h2 id="success-title">Recovery complete</h2>
      <p class="success">Your password was updated and the privacy conditions were accepted. You may now safely continue with appointment arrangements.</p>
    </section>

    <aside aria-labelledby="safety-title">
      <h2 id="safety-title">Stay safe</h2>
      <p>Hospital staff will never ask for your password or recovery code. Do not follow recovery links sent by unknown people, and do not reuse this password on other services.</p>
    </aside>

    <aside id="logs" aria-labelledby="logs-title">
      <h2 id="logs-title">Logs</h2>
      <p class="small">Simulated delivery and verification events are mirrored here.</p>
      <pre id="logOutput" aria-live="polite">Ready.</pre>
    </aside>
  </main>

  <script nonce="{{NONCE}}">
    /* Client safeguards for requirements 2 & 5: no unsafe HTML insertion or remote requests. */
    (() => {
      "use strict";
      const csrf = ${JSON.stringify(csrf)};
      const byId = (id) => document.getElementById(id);
      const stages = ["recoveryStage", "tokenStage", "mfaStage", "passwordStage", "privacyStage", "successStage"];
      const logOutput = byId("logOutput");

      function log(message) {
        console.log(message);
        const line = document.createTextNode(message + "\\n");
        logOutput.appendChild(line);
      }

      function show(stageId) {
        stages.forEach((id) => byId(id).classList.toggle("hidden", id !== stageId));
        byId(stageId).querySelector("input, button, a")?.focus();
      }

      function error(id, message) {
        byId(id).textContent = message || "";
      }

      async function post(path, data) {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-Requested-With": "RecoverySPA" },
          body: JSON.stringify({ ...data, csrf })
        });
        const result = await response.json().catch(() => ({ ok: false, message: "Unable to complete request." }));
        if (!response.ok && !result.message) result.message = "Unable to complete request.";
        return result;
      }

      function hashToken() {
        const hash = location.hash;
        if (!hash.startsWith("#token=")) return;
        const value = hash.slice(7);
        try {
          const token = decodeURIComponent(value);
          if (/^[a-f0-9]{64}$/i.test(token)) {
            byId("token").value = token;
            show("tokenStage");
            log("Recovery link detected. Code ready for secure verification.");
          }
        } catch (_) {
          // Invalid fragments are ignored and never rendered.
        }
      }

      byId("recoveryForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        error("recoveryError", "");
        const account = byId("account").value.trim();
        if (!account) {
          error("recoveryError", "Enter an email address or account reference.");
          return;
        }
        const result = await post("/api/recovery", { account });
        if (!result.ok) {
          error("recoveryError", result.message);
          return;
        }
        const token = String(result.testToken || "");
        byId("testToken").textContent = token;
        byId("token").value = token;
        const link = location.pathname + "#token=" + encodeURIComponent(token);
        byId("recoveryLink").setAttribute("href", link);
        log("SIMULATED RECOVERY DELIVERY — test code: " + token);
        show("tokenStage");
      });

      byId("tokenForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        error("tokenError", "");
        const token = byId("token").value.trim();
        const result = await post("/api/verify-reset", { token });
        if (!result.ok) {
          error("tokenError", result.message);
          return;
        }
        log("Recovery code verified.");
        log("SIMULATED MFA DELIVERY — security code: " + String(result.testMfaCode));
        show("mfaStage");
      });

      byId("mfaForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        error("mfaError", "");
        const result = await post("/api/verify-mfa", { code: byId("mfa").value.trim() });
        if (!result.ok) {
          error("mfaError", result.message);
          return;
        }
        log("MFA verification completed.");
        show("passwordStage");
      });

      byId("passwordForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        error("passwordError", "");
        const password = byId("password").value;
        const confirmation = byId("confirmPassword").value;
        if (password !== confirmation) {
          error("passwordError", "The password confirmation does not match.");
          return;
        }
        const localPolicy = password.length >= 12 && /[a-z]/.test(password) && /[A-Z]/.test(password) &&
          /[0-9]/.test(password) && /[^A-Za-z0-9\\s]/.test(password) && !/\\s/.test(password);
        if (!localPolicy) {
          error("passwordError", "Use 12+ characters with uppercase, lowercase, number, symbol, and no spaces.");
          return;
        }
        const result = await post("/api/password", { password });
        byId("password").value = "";
        byId("confirmPassword").value = "";
        if (!result.ok) {
          error("passwordError", result.message);
          return;
        }
        log("Password reset completed. Plaintext password was not logged.");
        show("privacyStage");
      });

      byId("privacyForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        error("privacyError", "");
        if (!byId("privacyCheck").checked) {
          error("privacyError", "Please confirm acceptance to continue.");
          return;
        }
        const result = await post("/api/privacy", { accepted: true });
        if (!result.ok) {
          error("privacyError", result.message);
          return;
        }
        log("Updated privacy conditions accepted.");
        show("successStage");
      });

      window.addEventListener("hashchange", hashToken);
      hashToken();
    })();
  </script>
</body>
</html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const session = getSession(request);
  if (!session) return genericError(403);

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body)) return genericError();
  const data = body as Record<string, unknown>;
  if (!validCsrf(request, session, data)) return genericError(403);

  if (pathname === "/api/recovery") {
    if (tooMany(session, "recoveryAttempts", "recoveryWindowStart", 5)) {
      return jsonResponse({ ok: false, message: "Please wait before requesting another recovery code." }, 429);
    }
    // Account input is intentionally neither retained nor returned (requirements 1, 3, and 4).
    if (typeof data.account !== "string" || data.account.length < 1 || data.account.length > 160) {
      return jsonResponse({ ok: false, message: "Enter a valid account reference." });
    }

    const token = randomToken(32);
    session.reset = {
      digest: await digest(token),
      expiresAt: Date.now() + RESET_TTL,
      tokenConsumed: false,
      verified: false,
      passwordCompleted: false,
    };
    session.mfa = undefined;
    session.mfaVerified = false;
    session.passwordUpdated = false;
    session.privacyAccepted = false;

    return jsonResponse({
      ok: true,
      message: "If an eligible account exists, instructions have been prepared.",
      testToken: token,
    });
  }

  if (pathname === "/api/verify-reset") {
    const token = typeof data.token === "string" ? data.token : "";
    const reset = session.reset;

    /*
      Recovery token consumption is separate from password completion.
      The token is atomically consumed before MFA state is created, so a
      repeated submission cannot replace or recreate the MFA challenge.
    */
    if (
      !/^[a-f0-9]{64}$/i.test(token) ||
      !reset ||
      reset.tokenConsumed ||
      reset.expiresAt < Date.now()
    ) {
      return jsonResponse({ ok: false, message: "That recovery code is invalid, expired, or has already been used." });
    }

    if (!constantTimeEqual(await digest(token), reset.digest)) {
      return jsonResponse({ ok: false, message: "That recovery code is invalid, expired, or has already been used." });
    }

    // Consume first; JavaScript request handling cannot interleave this synchronous state update.
    reset.tokenConsumed = true;
    reset.verified = true;

    // Deterministic mock MFA, issued only for the first successful token verification.
    session.mfa = {
      code: "246810",
      expiresAt: Date.now() + MFA_TTL,
      attempts: 0,
      lockedUntil: 0,
    };
    session.mfaVerified = false;

    return jsonResponse({ ok: true, testMfaCode: "246810" });
  }

  if (pathname === "/api/verify-mfa") {
    const mfa = session.mfa;
    const code = typeof data.code === "string" ? data.code : "";

    if (!session.reset?.verified || !session.reset.tokenConsumed || !mfa || mfa.expiresAt < Date.now()) {
      return jsonResponse({ ok: false, message: "The security code is no longer valid. Start recovery again." });
    }
    if (mfa.lockedUntil > Date.now()) {
      return jsonResponse({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    mfa.attempts++;
    if (!constantTimeEqual(code, mfa.code)) {
      if (mfa.attempts >= 5) mfa.lockedUntil = Date.now() + 5 * 60 * 1000;
      return jsonResponse({ ok: false, message: "The security code is not valid. Please try again." });
    }

    session.mfaVerified = true;
    return jsonResponse({ ok: true });
  }

  if (pathname === "/api/password") {
    const reset = session.reset;

    /*
      A consumed token remains a valid authorization record for this one
      verified, MFA-authorized password update. passwordCompleted is an
      independent duplicate-completion guard.
    */
    if (reset?.passwordCompleted || session.passwordUpdated) {
      return jsonResponse({ ok: false, message: "This recovery password update has already been completed. Start recovery again if needed." }, 409);
    }

    if (tooMany(session, "passwordAttempts", "passwordWindowStart", 5)) {
      return jsonResponse({ ok: false, message: "Please wait before trying another password." }, 429);
    }

    if (!reset || !reset.tokenConsumed || !reset.verified || !session.mfaVerified) {
      return jsonResponse({ ok: false, message: "Complete recovery code and security code verification first." }, 403);
    }

    const password = typeof data.password === "string" ? data.password : "";
    const policyFailure = passwordPolicy(password);
    if (policyFailure) return jsonResponse({ ok: false, message: policyFailure });

    /* Security requirement 4: bcrypt hash only; plaintext is never stored, returned, or logged. */
    session.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    reset.passwordCompleted = true;
    session.passwordUpdated = true;

    return jsonResponse({ ok: true });
  }

  if (pathname === "/api/privacy") {
    if (!session.reset?.passwordCompleted || !session.passwordUpdated || !session.mfaVerified || data.accepted !== true) {
      return jsonResponse({ ok: false, message: "Secure recovery must be completed before accepting conditions." }, 403);
    }
    // No client-controlled patient/account/resource identifier is accepted.
    session.privacyAccepted = true;
    return jsonResponse({ ok: true });
  }

  return genericError(404);
}

async function fetchHandler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const existing = getSession(request);
      const created = existing ? undefined : makeSession();
      const session = existing || created!.session;
      return htmlResponse(page(session.csrf), created?.id || cookieValue(request, "__Host-recovery_session") || "");
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) {
      return await handleApi(request, url.pathname);
    }

    return new Response("Not found.", { status: 404, headers: securityHeaders() });
  } catch {
    // Requirements 3 and 5: no stack traces or diagnostic detail to clients.
    return new Response("Service temporarily unavailable.", { status: 503, headers: securityHeaders() });
  }
}

const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");

if (await certFile.exists() && await keyFile.exists()) {
  Bun.serve({
    hostname,
    port,
    tls: { cert: certFile, key: keyFile },
    fetch: fetchHandler,
  });
} else {
  // Safe failure: no recovery endpoints or sessions are exposed when TLS material is absent.
  Bun.serve({
    hostname,
    port,
    fetch() {
      const headers = securityHeaders();
      headers.set("Content-Type", "text/plain; charset=utf-8");
      return new Response("Secure service unavailable. TLS certificates are required.", { status: 503, headers });
    },
  });
}
