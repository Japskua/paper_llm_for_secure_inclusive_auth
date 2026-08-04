
const HTTPS_PORT = 3000;
const HTTP_REJECTION_PORT = 3001;
const SESSION_COOKIE = "__Host-recovery";
const SESSION_TTL_MS = 30 * 60 * 1000;
const RESET_TTL_MS = 15 * 60 * 1000;
const MFA_TTL_MS = 15 * 60 * 1000;
const MOCK_ACCOUNT_EMAIL = "helena@example.test";
const MFA_CODE = "482913";

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  requestAttempts: number[];
  resetGuessAttempts: number[];
  mfaAttempts: number[];
  resetToken?: string;
  resetValidated: boolean;
  resetExpiresAt?: number;
  resetUsed: boolean;
  passwordHash?: string;
  mfaIssued: boolean;
  mfaExpiresAt?: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
};

const sessions = new Map<string, Session>();

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
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

function sessionFromRequest(request: Request): Session | undefined {
  const sid = parseCookies(request)[SESSION_COOKIE];
  if (!sid) return undefined;
  const session = sessions.get(sid);
  if (!session || Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(sid);
    return undefined;
  }
  return session;
}

function createSession(): Session {
  const session: Session = {
    id: randomToken(32),
    csrf: randomToken(32),
    createdAt: Date.now(),
    requestAttempts: [],
    resetGuessAttempts: [],
    mfaAttempts: [],
    resetValidated: false,
    resetUsed: false,
    mfaIssued: false,
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
  };
  sessions.set(session.id, session);
  return session;
}

function trimAttempts(attempts: number[], windowMs: number): number[] {
  const cutoff = Date.now() - windowMs;
  return attempts.filter((time) => time >= cutoff);
}

function rateAllowed(
  session: Session,
  field: "requestAttempts" | "resetGuessAttempts" | "mfaAttempts",
  limit: number,
  windowMs: number,
): boolean {
  session[field] = trimAttempts(session[field], windowMs);
  if (session[field].length >= limit) return false;
  session[field].push(Date.now());
  return true;
}

function normalizedHostname(hostname: string): string {
  return hostname === "[::1]" ? "::1" : hostname;
}

// Requirements 1 and 3: strict local HTTPS origin validation plus per-session CSRF.
function allowedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const url = new URL(origin);
    const hostname = normalizedHostname(url.hostname);
    return url.protocol === "https:" &&
      (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") &&
      url.port === String(HTTPS_PORT);
  } catch {
    return false;
  }
}

function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token") || "";
  return allowedOrigin(request) && token.length > 0 && token === session.csrf;
}

function passwordValid(password: unknown): password is string {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9\s]/.test(password) &&
    !/\s/.test(password);
}

function localHttpsRequest(request: Request): boolean {
  try {
    const url = new URL(request.url);
    const hostname = normalizedHostname(url.hostname);
    return url.protocol === "https:" &&
      (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1");
  } catch {
    return false;
  }
}

function headers(nonce: string, contentType = "application/json; charset=utf-8"): Headers {
  return new Headers({
    "content-type": contentType,
    "cache-control": "no-store, max-age=0",
    "pragma": "no-cache",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "img-src 'self' data:",
      "font-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
  });
}

function json(data: Record<string, unknown>, status = 200, nonce = randomToken(16), extra?: HeadersInit): Response {
  const responseHeaders = headers(nonce);
  if (extra) {
    for (const [key, value] of new Headers(extra)) responseHeaders.set(key, value);
  }
  return new Response(JSON.stringify(data), { status, headers: responseHeaders });
}

async function bodyJson(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Recovery Portal</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --blue:#075a9f; --ink:#14212b; --muted:#52616c; --line:#c9d4dc; --soft:#f2f7fa; --good:#126a41; --warn:#8a4b00; }
    * { box-sizing:border-box; }
    body { margin:0; background:#edf3f6; color:var(--ink); font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    header { background:#fff; border-bottom:4px solid var(--blue); }
    .bar, main, footer { max-width:820px; margin:auto; padding-left:24px; padding-right:24px; }
    .bar { min-height:86px; display:flex; align-items:center; justify-content:space-between; gap:20px; }
    h1 { font-size:1.32rem; margin:0; } h2 { margin-top:0; font-size:1.45rem; }
    nav { display:flex; gap:8px; flex-wrap:wrap; }
    main { padding-top:28px; padding-bottom:24px; }
    .card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:26px; box-shadow:0 2px 9px #18354a12; }
    .card + .card { margin-top:20px; }
    p { margin:0 0 16px; } .muted { color:var(--muted); }
    label { display:block; margin:16px 0 6px; font-weight:650; }
    input { width:100%; padding:11px; border:1px solid #8495a1; border-radius:5px; font:inherit; }
    input:focus, button:focus { outline:3px solid #8cc7ec; outline-offset:2px; }
    button { border:1px solid #075a9f; border-radius:5px; padding:10px 15px; background:var(--blue); color:#fff; font:inherit; font-weight:650; cursor:pointer; }
    button.secondary { background:#fff; color:#075a9f; } button:disabled { opacity:.55; cursor:not-allowed; }
    .actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:21px; }
    .notice { border-left:4px solid var(--blue); background:var(--soft); padding:14px 16px; margin:0 0 20px; }
    .notice strong { display:block; margin-bottom:4px; }
    .status { min-height:24px; margin-top:16px; font-weight:600; } .status.error { color:#9b1c1c; } .status.ok { color:var(--good); }
    .checkline { display:flex; gap:10px; align-items:flex-start; margin-top:18px; } .checkline input { width:auto; margin-top:5px; }
    ul { padding-left:21px; } code { background:#eaf0f3; padding:1px 4px; border-radius:3px; }
    details summary { cursor:pointer; font-weight:650; } pre { white-space:pre-wrap; word-break:break-word; margin:10px 0 0; font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; }
    footer { padding-bottom:28px; color:var(--muted); font-size:.9rem; }
    @media (max-width:560px) { .bar { padding-top:16px; padding-bottom:16px; align-items:flex-start; flex-direction:column; } .card { padding:20px; } }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <h1>Local Health Portal — Account Recovery</h1>
      <nav aria-label="Recovery navigation">
        <button class="secondary" type="button" data-screen="request">Request reset</button>
        <button class="secondary" type="button" data-screen="verify">Enter reset code</button>
      </nav>
    </div>
  </header>
  <main>
    <div class="notice" role="note">
      <strong>Protect your account</strong>
      Verify that this is the <code>https://localhost:3000</code> portal. Never share a password, reset link, or verification code by email, phone, or chat. Hospital staff will not ask for them.
    </div>
    <div id="status" class="status" role="status" aria-live="polite"></div>
    <section id="app" aria-live="polite" aria-busy="true"></section>
    <section class="card" aria-labelledby="logs-title">
      <details>
        <summary id="logs-title">Logs (simulated delivery and verification events)</summary>
        <pre id="logs" aria-live="polite">Waiting for secure session…</pre>
      </details>
    </section>
  </main>
  <footer>Demo recovery flow. Delivery is simulated locally; no email, SMS, or external service is contacted.</footer>
  <script nonce="${nonce}">
    (() => {
      "use strict";
      const app = document.getElementById("app");
      const status = document.getElementById("status");
      const logs = document.getElementById("logs");
      const state = { csrf: "", resetCode: "", screen: "request" };
      const allowedScreens = new Set(["request", "verify", "password", "mfa", "privacy", "confirmed"]);

      // Requirements 2 and 5: all UI content is constructed with DOM/text APIs, never injected HTML.
      function node(tag, text, attrs) {
        const element = document.createElement(tag);
        if (text !== undefined && text !== null) element.textContent = text;
        if (attrs) for (const [key, value] of Object.entries(attrs)) {
          if (key === "className") element.className = value;
          else element.setAttribute(key, value);
        }
        return element;
      }
      function log(message) {
        console.log(message);
        logs.textContent = (logs.textContent === "Waiting for secure session…" ? "" : logs.textContent + "\\n") + message;
      }
      function setStatus(message, error) {
        status.textContent = message || "";
        status.className = "status " + (message ? (error ? "error" : "ok") : "");
      }
      function button(label, type, className) {
        return node("button", label, { type: type || "button", className: className || "" });
      }
      function field(form, labelText, inputType, name, autocomplete) {
        const label = node("label", labelText, { for: name });
        const input = node("input", undefined, { id: name, name, type: inputType, required: "required", autocomplete: autocomplete || "off" });
        form.append(label, input);
        return input;
      }
      async function api(path, method, payload) {
        const options = { method, credentials: "same-origin", headers: {} };
        if (method !== "GET") {
          options.headers["content-type"] = "application/json";
          options.headers["x-csrf-token"] = state.csrf;
          options.body = JSON.stringify(payload || {});
        }
        const response = await fetch(path, options);
        let data = {};
        try { data = await response.json(); } catch { data = { message: "The secure service could not process that request." }; }
        if (!response.ok) throw Object.assign(new Error(data.message || "Request could not be completed."), { data, status: response.status });
        return data;
      }
      function go(screen) {
        if (!allowedScreens.has(screen)) return;
        state.screen = screen;
        setStatus("");
        render();
      }
      function render() {
        app.replaceChildren();
        app.setAttribute("aria-busy", "false");
        if (state.screen === "request") requestScreen();
        else if (state.screen === "verify") verifyScreen();
        else if (state.screen === "password") passwordScreen();
        else if (state.screen === "mfa") mfaScreen();
        else if (state.screen === "privacy") privacyScreen();
        else confirmedScreen();
      }

      // Requirements 4 and 5: privacy-preserving request and phishing-safe guidance.
      function requestScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "request-title" });
        section.append(node("h2", "Reset your password", { id: "request-title" }));
        section.append(node("p", "Enter the email address used for the account. For privacy, the response is the same whether or not an account is available."));
        const form = node("form");
        const email = field(form, "Account email", "email", "email", "email");
        const actions = node("div", undefined, { className: "actions" });
        actions.append(button("Send reset instructions", "submit"));
        form.append(actions);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (!email.validity.valid) { setStatus("Enter a valid email address.", true); return; }
          try {
            const data = await api("/api/reset-request", "POST", { email: email.value.trim() });
            setStatus(data.message, false);
            state.resetCode = data.mockDeliveryToken || "";
            log("SIMULATED RESET DELIVERY: reset code " + data.mockDeliveryToken + ". Enter it manually in the verification screen. Never share this code.");
            const next = button("Enter reset code", "button", "secondary");
            next.addEventListener("click", () => go("verify"));
            actions.append(next);
          } catch (error) { setStatus(error.message, true); }
        });
        section.append(form);
        app.append(section);
      }

      function verifyScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "verify-title" });
        section.append(node("h2", "Verify reset code", { id: "verify-title" }));
        section.append(node("p", "Paste or type the reset code from the simulated delivery log. Reset codes expire and can be used for one password reset only."));
        const form = node("form");
        const code = field(form, "Reset code", "text", "reset-code", "one-time-code");
        code.maxLength = 100;
        const actions = node("div", undefined, { className: "actions" });
        actions.append(button("Verify code", "submit"), button("Request another code", "button", "secondary"));
        actions.lastChild.addEventListener("click", () => go("request"));
        form.append(actions);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          const value = code.value.trim();
          if (!/^[A-Za-z0-9_-]{20,100}$/.test(value)) { setStatus("Enter a valid reset code format.", true); return; }
          try {
            const data = await api("/api/reset-validate", "POST", { token: value });
            state.resetCode = value;
            setStatus(data.message, false);
            go("password");
          } catch (error) { setStatus(error.message, true); }
        });
        section.append(form);
        app.append(section);
      }

      function passwordScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "password-title" });
        section.append(node("h2", "Create a new password", { id: "password-title" }));
        section.append(node("p", "Use at least 12 characters with uppercase, lowercase, a number, and a symbol. Spaces are not allowed."));
        const form = node("form");
        const first = field(form, "New password", "password", "new-password", "new-password");
        first.maxLength = 128;
        const second = field(form, "Confirm new password", "password", "confirm-password", "new-password");
        second.maxLength = 128;
        const actions = node("div", undefined, { className: "actions" });
        actions.append(button("Update password", "submit"));
        form.append(actions);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (first.value !== second.value) { setStatus("The passwords do not match.", true); return; }
          if (first.value.length < 12 || !/[a-z]/.test(first.value) || !/[A-Z]/.test(first.value) || !/\\d/.test(first.value) || !/[^A-Za-z0-9\\s]/.test(first.value) || /\\s/.test(first.value)) {
            setStatus("Choose a password matching the stated policy.", true); return;
          }
          try {
            const data = await api("/api/password-update", "POST", { token: state.resetCode, password: first.value });
            first.value = ""; second.value = "";
            state.resetCode = "";
            setStatus(data.message, false);
            log("SIMULATED MFA DELIVERY: verification code " + data.mockMfaCode + ". Enter it manually. Never share this code.");
            go("mfa");
          } catch (error) { first.value = ""; second.value = ""; setStatus(error.message, true); }
        });
        section.append(form);
        app.append(section);
      }

      function mfaScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "mfa-title" });
        section.append(node("h2", "Confirm your identity", { id: "mfa-title" }));
        section.append(node("p", "Enter the six-digit code from the simulated local delivery log to finish recovery."));
        const form = node("form");
        const code = field(form, "Verification code", "text", "mfa-code", "one-time-code");
        code.inputMode = "numeric"; code.maxLength = 6;
        const actions = node("div", undefined, { className: "actions" });
        actions.append(button("Verify and continue", "submit"));
        form.append(actions);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (!/^\\d{6}$/.test(code.value.trim())) { setStatus("Enter a six-digit verification code.", true); return; }
          try {
            const data = await api("/api/mfa-verify", "POST", { code: code.value.trim() });
            code.value = "";
            setStatus(data.message, false);
            log("MFA verification completed for this secure browser session.");
            go("privacy");
          } catch (error) { code.value = ""; setStatus(error.message, true); }
        });
        section.append(form);
        app.append(section);
      }

      function privacyScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "privacy-title" });
        section.append(node("h2", "Updated privacy conditions", { id: "privacy-title" }));
        section.append(node("p", "Please review and accept the updated privacy conditions before an appointment can be confirmed."));
        const list = node("ul");
        ["Your account access is protected by authentication.", "Only necessary information is used to arrange care.", "You can contact the hospital through verified channels with questions."].forEach((text) => list.append(node("li", text)));
        section.append(list);
        const form = node("form");
        const checkline = node("label", undefined, { className: "checkline" });
        const check = node("input", undefined, { type: "checkbox", id: "privacy-check" });
        checkline.append(check, node("span", "I have reviewed and accept the updated privacy conditions."));
        form.append(checkline);
        const actions = node("div", undefined, { className: "actions" });
        actions.append(button("Accept and continue", "submit"));
        form.append(actions);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (!check.checked) { setStatus("Please confirm acceptance before continuing.", true); return; }
          try {
            const data = await api("/api/privacy-accept", "POST", { accepted: true });
            setStatus(data.message, false);
            go("confirmed");
          } catch (error) { setStatus(error.message, true); }
        });
        section.append(form);
        app.append(section);
      }

      function confirmedScreen() {
        const section = node("section", undefined, { className: "card", "aria-labelledby": "confirmation-title" });
        const title = node("h2", "Privacy conditions accepted", { id: "confirmation-title" });
        const progress = node("p", "Your privacy-condition acceptance has been recorded. Your appointment request is ready for confirmation.");
        section.append(title, progress);
        section.append(node("p", "For your safety, do not send account credentials or verification codes to anyone."));
        const actions = node("div", undefined, { className: "actions" });
        const confirm = button("Confirm appointment request", "button");
        confirm.addEventListener("click", async () => {
          try {
            const data = await api("/api/appointment-confirm", "POST", {});
            title.textContent = "Appointment request confirmed";
            progress.textContent = "Your privacy-condition acceptance and appointment request have been recorded for this authenticated session.";
            setStatus(data.message, false);
            confirm.disabled = true;
            log("Appointment confirmation recorded in this secure mock session.");
          } catch (error) { setStatus(error.message, true); }
        });
        actions.append(confirm);
        section.append(actions);
        app.append(section);
      }

      document.querySelectorAll("[data-screen]").forEach((item) => item.addEventListener("click", () => go(item.getAttribute("data-screen"))));
      (async () => {
        try {
          const response = await fetch("/api/bootstrap", { credentials: "same-origin" });
          const data = await response.json();
          if (!response.ok || !data.csrf) throw new Error("Unable to start a secure session.");
          state.csrf = data.csrf;
          log("Secure local session established. No external network delivery is used.");
          render();
        } catch (error) {
          app.replaceChildren(node("section", "Unable to establish a secure session. Please use https://localhost:3000.", { className: "card" }));
          app.setAttribute("aria-busy", "false");
          setStatus(error.message || "Secure session unavailable.", true);
        }
      })();
    })();
  </script>
</body>
</html>`;
}

async function handle(request: Request): Promise<Response> {
  const nonce = randomToken(16);
  if (!localHttpsRequest(request)) return json({ message: "HTTPS access is required." }, 421, nonce);

  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/") {
    return new Response(appHtml(nonce), { headers: headers(nonce, "text/html; charset=utf-8") });
  }

  if (request.method === "GET" && url.pathname === "/api/bootstrap") {
    let session = sessionFromRequest(request);
    let cookie: string | undefined;
    if (!session) {
      session = createSession();
      // Requirements 1 and 3: host-only, HttpOnly, Secure, SameSite session cookie.
      cookie = `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
    }
    return json({ csrf: session.csrf }, 200, nonce, cookie ? { "set-cookie": cookie } : undefined);
  }

  if (request.method !== "POST" || !url.pathname.startsWith("/api/")) {
    return json({ message: "Not found." }, 404, nonce);
  }

  const session = sessionFromRequest(request);
  if (!session) return json({ message: "Your secure session has expired. Start recovery again." }, 401, nonce);
  if (!csrfValid(request, session)) return json({ message: "This request could not be verified. Refresh and try again." }, 403, nonce);

  const data = await bodyJson(request);
  if (!data) return json({ message: "Request could not be processed." }, 400, nonce);

  // Requirements 1, 3, 4: generic response and opaque mock code for every valid-format email.
  // Only the known mock account's code is retained server-side and can advance recovery.
  if (url.pathname === "/api/reset-request") {
    if (!rateAllowed(session, "requestAttempts", 3, 15 * 60 * 1000)) {
      return json({ message: "Too many reset requests. Please wait before trying again." }, 429, nonce);
    }

    const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
    const validFormat = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);
    const knownMockAccount = validFormat && email === MOCK_ACCOUNT_EMAIL;
    const opaqueDeliveryToken = randomToken(32);

    if (knownMockAccount) {
      session.resetToken = opaqueDeliveryToken;
      session.resetValidated = false;
      session.resetUsed = false;
      session.resetExpiresAt = Date.now() + RESET_TTL_MS;
      session.mfaIssued = false;
      session.authenticated = false;
      session.privacyAccepted = false;
      session.appointmentConfirmed = false;
    }

    return json({
      message: "If an eligible account exists, reset instructions have been prepared.",
      mockDeliveryToken: opaqueDeliveryToken,
    }, 200, nonce);
  }

  if (url.pathname === "/api/reset-validate") {
    if (!rateAllowed(session, "resetGuessAttempts", 5, 15 * 60 * 1000)) {
      return json({ message: "Too many code attempts. Request a new reset code later." }, 429, nonce);
    }
    const token = typeof data.token === "string" ? data.token : "";
    const valid = session.resetToken &&
      !session.resetUsed &&
      session.resetExpiresAt &&
      Date.now() <= session.resetExpiresAt &&
      token.length > 0 &&
      token === session.resetToken;
    if (!valid) return json({ message: "That reset code is invalid, expired, or has already been used." }, 400, nonce);
    session.resetValidated = true;
    return json({ message: "Reset code verified. Choose a new password." }, 200, nonce);
  }

  // Requirement 4: password never logged or returned; Bun bcrypt hash only is retained.
  if (url.pathname === "/api/password-update") {
    const token = typeof data.token === "string" ? data.token : "";
    const password = data.password;
    const validToken = session.resetToken &&
      session.resetValidated &&
      !session.resetUsed &&
      session.resetExpiresAt &&
      Date.now() <= session.resetExpiresAt &&
      token === session.resetToken;
    if (!validToken) return json({ message: "Your reset code is no longer valid. Start a new recovery request." }, 400, nonce);
    if (!passwordValid(password)) {
      return json({ message: "Password must have 12+ characters, uppercase, lowercase, number, symbol, and no spaces." }, 400, nonce);
    }

    session.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 12 });
    session.resetUsed = true;
    session.resetValidated = false;
    session.resetToken = undefined;
    session.mfaIssued = true;
    session.mfaExpiresAt = Date.now() + MFA_TTL_MS;
    return json({
      message: "Password updated. Confirm your identity with the verification code.",
      mockMfaCode: MFA_CODE,
    }, 200, nonce);
  }

  if (url.pathname === "/api/mfa-verify") {
    if (!rateAllowed(session, "mfaAttempts", 5, 15 * 60 * 1000)) {
      return json({ message: "Too many verification attempts. Start recovery again later." }, 429, nonce);
    }
    const code = typeof data.code === "string" ? data.code : "";
    if (!session.mfaIssued || !session.mfaExpiresAt || Date.now() > session.mfaExpiresAt || code !== MFA_CODE) {
      return json({ message: "That verification code is invalid or expired." }, 400, nonce);
    }
    session.authenticated = true;
    session.mfaIssued = false;
    return json({ message: "Identity confirmed. You may review the privacy conditions." }, 200, nonce);
  }

  // Requirements 1 and 4: authenticated state is owned solely by the server-side session.
  if (url.pathname === "/api/privacy-accept") {
    if (!session.authenticated) return json({ message: "Authentication is required before accepting conditions." }, 401, nonce);
    if (data.accepted !== true) return json({ message: "Acceptance confirmation is required." }, 400, nonce);
    session.privacyAccepted = true;
    return json({ message: "Privacy conditions accepted. You can confirm the appointment request." }, 200, nonce);
  }

  if (url.pathname === "/api/appointment-confirm") {
    if (!session.authenticated || !session.privacyAccepted) {
      return json({ message: "Authentication and privacy-condition acceptance are required." }, 401, nonce);
    }
    session.appointmentConfirmed = true;
    return json({ message: "Appointment request confirmed for this secure session." }, 200, nonce);
  }

  return json({ message: "Not found." }, 404, nonce);
}

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, session] of sessions) if (session.createdAt < cutoff) sessions.delete(id);
}, 5 * 60 * 1000).unref();

// Requirement 3: TLS is mandatory. Certificates are supplied at the documented paths.
Bun.serve({
  port: HTTPS_PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      // Requirement 3: no stack traces or debugging details reach the browser.
      return json({ message: "The secure service is temporarily unavailable." }, 500);
    }
  },
});

// Requirement 3: HTTP has no application routes or cookies; reject rather than permit downgrade.
Bun.serve({
  port: HTTP_REJECTION_PORT,
  hostname: "0.0.0.0",
  fetch() {
    return new Response("HTTPS is required. Use https://localhost:3000/", {
      status: 426,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  },
});

console.log(`Secure recovery portal listening at https://localhost:${HTTPS_PORT}`);
