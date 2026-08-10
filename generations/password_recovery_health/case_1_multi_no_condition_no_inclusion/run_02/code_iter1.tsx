
/*
  Password Recovery System — single-file Bun HTTPS server and vanilla-JS SPA.

  Security requirement mapping:
  1. Session/CSRF/access control: opaque Secure HttpOnly sessions, per-session CSRF,
     protected state-changing API routes, and server-side authorization checks.
  2. Injection/XSS: CSP nonce, no dynamic HTML interpolation, client textContent only.
  3. HTTPS/headers/tokens: TLS-only server, secure headers, random expiring one-use tokens.
  4. Authentication: bcrypt password hashing, password policy, MFA and throttling.
  5. Anti-phishing: same-origin navigation only and safe-authentication guidance.
*/

type RecoveryState = {
  token: string;
  expiresAt: number;
  used: boolean;
  accountRef: string;
};

type AttemptState = {
  failures: number;
  blockedUntil: number;
};

type SessionState = {
  csrf: string;
  recovery?: RecoveryState;
  resetAuthorized: boolean;
  mfaPending: boolean;
  authenticated: boolean;
  accountRef?: string;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
  tokenAttempts: AttemptState;
  mfaAttempts: AttemptState;
};

const sessions = new Map<string, SessionState>();

/* No patient-facing identifier is stored or returned by the UI/API. */
const protectedAccount = {
  passwordHash: "",
  privacyAccepted: false,
};

const SESSION_COOKIE = "__Host-recovery_session";
const TOKEN_TTL_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const BLOCK_MS = 60 * 1000;
const MFA_TEST_CODE = "246810";

function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  let binary = "";
  for (const value of values) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function equalSecurely(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let i = 0; i < left.length; i++) {
    different |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return different === 0;
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return result;
}

/* Requirement 1: cryptographically random opaque session plus unique CSRF value. */
function makeSession(): { id: string; state: SessionState } {
  const id = randomValue(32);
  const state: SessionState = {
    csrf: randomValue(32),
    resetAuthorized: false,
    mfaPending: false,
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
    tokenAttempts: { failures: 0, blockedUntil: 0 },
    mfaAttempts: { failures: 0, blockedUntil: 0 },
  };
  sessions.set(id, state);
  return { id, state };
}

function sessionFor(request: Request): { id: string; state: SessionState; newCookie?: string } {
  const cookies = parseCookies(request);
  const existing = cookies[SESSION_COOKIE];
  if (existing && sessions.has(existing)) {
    return { id: existing, state: sessions.get(existing)! };
  }

  const created = makeSession();
  return {
    ...created,
    newCookie: `${SESSION_COOKIE}=${encodeURIComponent(created.id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`,
  };
}

function nonce(): string {
  return randomValue(18);
}

/* Requirement 3: restrictive production-safe HTTPS response headers. */
function securityHeaders(scriptNonce: string): Headers {
  const headers = new Headers();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${scriptNonce}'; style-src 'nonce-${scriptNonce}'; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`,
  );
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function apiHeaders(): Headers {
  const headers = new Headers();
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function json(data: Record<string, unknown>, status = 200, cookie?: string): Response {
  const headers = apiHeaders();
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400, message = "We could not complete that request. Please try again."): Response {
  return json({ ok: false, message }, status);
}

function csrfValid(request: Request, session: SessionState): boolean {
  const submitted = request.headers.get("x-csrf-token") || "";
  return submitted.length > 0 && equalSecurely(submitted, session.csrf);
}

function blocked(attempts: AttemptState): boolean {
  return attempts.blockedUntil > Date.now();
}

function registerFailure(attempts: AttemptState): void {
  attempts.failures += 1;
  if (attempts.failures >= MAX_FAILURES) {
    attempts.failures = 0;
    attempts.blockedUntil = Date.now() + BLOCK_MS;
  }
}

function resetAttempts(attempts: AttemptState): void {
  attempts.failures = 0;
  attempts.blockedUntil = 0;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    return data as Record<string, unknown>;
  } catch {
    return null;
  }
}

function validAccountIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  const email = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/;
  const identifier = /^[A-Za-z0-9._-]{3,80}$/;
  return trimmed.length <= 254 && (email.test(trimmed) || identifier.test(trimmed));
}

function passwordPolicy(password: unknown): password is string {
  return typeof password === "string"
    && password.length >= 12
    && password.length <= 128
    && /[a-z]/.test(password)
    && /[A-Z]/.test(password)
    && /\d/.test(password)
    && /[^A-Za-z0-9]/.test(password);
}

/* Requirement 1/4: all sensitive endpoint handlers use session, CSRF and server state only. */
async function handleApi(request: Request, url: URL): Promise<Response> {
  const sessionInfo = sessionFor(request);
  const { state } = sessionInfo;

  if (url.pathname === "/api/session" && request.method === "GET") {
    return json({
      ok: true,
      csrf: state.csrf,
      resetAuthorized: state.resetAuthorized,
      mfaPending: state.mfaPending,
      authenticated: state.authenticated,
      privacyAccepted: state.privacyAccepted,
      appointmentConfirmed: state.appointmentConfirmed,
    }, 200, sessionInfo.newCookie);
  }

  if (request.method !== "POST") return genericError(404, "The requested service is unavailable.");

  if (!csrfValid(request, state)) {
    return genericError(403, "Your secure session has expired. Refresh the page and try again.");
  }

  const body = await requestBody(request);
  if (!body) return genericError(400);

  if (url.pathname === "/api/recovery/request") {
    /*
      Requirement 4: This deliberately gives the same response for every valid account
      input and never reveals account existence. The input is never logged or reflected.
    */
    if (!validAccountIdentifier(body.identifier)) {
      return json({
        ok: true,
        message: "If the account can be recovered, secure recovery instructions have been prepared.",
      });
    }

    const token = randomValue(32);
    state.recovery = {
      token,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      used: false,
      accountRef: "protected-account",
    };
    state.resetAuthorized = false;
    state.mfaPending = false;

    return json({
      ok: true,
      message: "If the account can be recovered, secure recovery instructions have been prepared.",
      /* Local evaluation-only mock delivery; client logs it to browser console and Logs panel. */
      mockDeliveryToken: token,
      mockRecoveryLink: `/?view=verify&token=${encodeURIComponent(token)}`,
    });
  }

  if (url.pathname === "/api/recovery/verify") {
    const token = typeof body.token === "string" ? body.token.trim() : "";
    if (blocked(state.tokenAttempts)) {
      return genericError(429, "Too many unsuccessful attempts. Please wait one minute and try again.");
    }

    const recovery = state.recovery;
    const valid = !!recovery
      && !recovery.used
      && recovery.expiresAt > Date.now()
      && token.length === recovery.token.length
      && equalSecurely(token, recovery.token);

    if (!valid) {
      registerFailure(state.tokenAttempts);
      return genericError(400, "This recovery code is invalid, expired, or has already been used.");
    }

    recovery.used = true; // Requirement 3: one-time token consumption.
    state.resetAuthorized = true;
    resetAttempts(state.tokenAttempts);
    return json({ ok: true, message: "Recovery code verified." });
  }

  if (url.pathname === "/api/recovery/reset-password") {
    if (!state.resetAuthorized || !state.recovery || state.recovery.accountRef !== "protected-account") {
      return genericError(403, "Recovery verification is required before setting a password.");
    }

    if (!passwordPolicy(body.password)) {
      return genericError(400, "Use 12+ characters with uppercase, lowercase, a number, and a symbol.");
    }

    /*
      Requirement 4: bcrypt hash only; plaintext is not persisted or logged.
      Bun 1.3 provides Bun.password with bcrypt support.
    */
    protectedAccount.passwordHash = await Bun.password.hash(body.password as string, {
      algorithm: "bcrypt",
      cost: 10,
    });

    state.resetAuthorized = false;
    state.mfaPending = true;
    return json({
      ok: true,
      message: "Password updated. Complete the verification step.",
      mockMfaCode: MFA_TEST_CODE,
    });
  }

  if (url.pathname === "/api/mfa/verify") {
    if (!state.mfaPending) return genericError(403, "A password reset verification step is required.");
    if (blocked(state.mfaAttempts)) {
      return genericError(429, "Too many unsuccessful codes. Please wait one minute and try again.");
    }

    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!equalSecurely(code, MFA_TEST_CODE)) {
      registerFailure(state.mfaAttempts);
      return genericError(400, "The verification code could not be confirmed.");
    }

    resetAttempts(state.mfaAttempts);
    state.mfaPending = false;
    state.authenticated = true;
    state.accountRef = "protected-account";
    state.privacyAccepted = protectedAccount.privacyAccepted;
    return json({ ok: true, message: "Verification complete." });
  }

  if (url.pathname === "/api/privacy/accept") {
    if (!state.authenticated || state.accountRef !== "protected-account") {
      return genericError(403, "Please complete secure sign-in before continuing.");
    }

    protectedAccount.privacyAccepted = true;
    state.privacyAccepted = true;
    return json({ ok: true, message: "Privacy conditions accepted." });
  }

  if (url.pathname === "/api/appointment/confirm") {
    if (!state.authenticated || state.accountRef !== "protected-account" || !state.privacyAccepted) {
      return genericError(403, "Privacy acceptance and secure sign-in are required before confirmation.");
    }

    state.appointmentConfirmed = true;
    return json({ ok: true, message: "Your appointment request has been confirmed." });
  }

  return genericError(404, "The requested service is unavailable.");
}

function pageHtml(scriptNonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style nonce="${scriptNonce}">
    :root { color-scheme: light; --ink:#17243a; --blue:#075ca8; --soft:#edf5fb; --line:#c6d4e1; --danger:#a52424; --ok:#176c42; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f4f7fa; color:var(--ink); font:17px/1.55 Arial,Helvetica,sans-serif; }
    header { background:#073e70; color:white; padding:1.1rem 1.5rem; }
    header div, main, footer { max-width:760px; margin:auto; }
    h1 { font-size:1.35rem; margin:0; } h2 { margin-top:0; font-size:1.5rem; }
    main { margin-top:2rem; margin-bottom:1rem; background:white; border:1px solid var(--line); border-radius:10px; padding:clamp(1.2rem,4vw,2.4rem); }
    label { font-weight:bold; display:block; margin-top:1rem; }
    input { display:block; width:100%; margin-top:.35rem; padding:.7rem; border:1px solid #71849a; border-radius:5px; font:inherit; }
    button { cursor:pointer; border:0; border-radius:5px; padding:.72rem 1rem; margin-top:1.25rem; background:var(--blue); color:white; font:inherit; font-weight:bold; }
    button.secondary { color:#073e70; background:#e5eef6; margin-left:.5rem; } button:hover { filter:brightness(.93); }
    .notice { padding:.85rem 1rem; margin:1rem 0; border-radius:5px; background:var(--soft); border-left:4px solid var(--blue); }
    .error { background:#fff0f0; border-left-color:var(--danger); color:#7b1818; } .success { background:#effaf3; border-left-color:var(--ok); color:#155d38; }
    .guidance { background:#fff8e6; border:1px solid #edcf7b; padding:1rem; border-radius:6px; margin-top:1.5rem; }
    .logs { margin-top:1.7rem; border-top:1px solid var(--line); padding-top:1rem; }
    #log-list { background:#111d2b; color:#dcecff; border-radius:5px; padding:.8rem; min-height:3rem; max-height:180px; overflow:auto; font:13px/1.4 monospace; white-space:pre-wrap; }
    .muted { color:#53687d; } footer { padding:0 1.5rem 2rem; font-size:.9rem; }
    a { color:#075ca8; } ul { padding-left:1.25rem; }
  </style>
</head>
<body>
  <header><div><h1>Hospital account recovery</h1></div></header>
  <main id="app" aria-live="polite"><p>Loading secure recovery service…</p></main>
  <footer>Secure local demonstration. No patient details are displayed in this service.</footer>
  <script nonce="${scriptNonce}">
  (() => {
    "use strict";

    /* Requirement 2: all dynamic content is inserted with textContent, never innerHTML. */
    const app = document.getElementById("app");
    let csrf = "";
    let session = {};

    function el(tag, text) {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      return node;
    }

    function add(parent, tag, text, className) {
      const node = el(tag, text);
      if (className) node.className = className;
      parent.appendChild(node);
      return node;
    }

    function log(message) {
      console.log(message);
      const list = document.getElementById("log-list");
      if (list) {
        const line = el("div", message);
        list.appendChild(line);
        list.scrollTop = list.scrollHeight;
      }
    }

    async function api(path, payload) {
      const response = await fetch(path, {
        method: payload === undefined ? "GET" : "POST",
        credentials: "same-origin",
        headers: payload === undefined ? {} : {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf
        },
        body: payload === undefined ? undefined : JSON.stringify(payload)
      });
      let data;
      try { data = await response.json(); } catch { data = { ok:false, message:"Secure service unavailable." }; }
      return data;
    }

    function safeView() {
      const allowed = new Set(["recovery", "verify", "reset", "mfa", "privacy", "appointment", "confirmed"]);
      const requested = new URLSearchParams(location.search).get("view") || "recovery";
      return allowed.has(requested) ? requested : "recovery";
    }

    function go(view, token) {
      const params = new URLSearchParams();
      params.set("view", view);
      if (token) params.set("token", token);
      history.pushState({}, "", "/?" + params.toString());
      render();
    }

    function message(parent, text, kind) {
      return add(parent, "div", text, "notice " + (kind || ""));
    }

    function guidance(parent) {
      const box = add(parent, "aside", undefined, "guidance");
      box.setAttribute("aria-label", "Safe authentication guidance");
      add(box, "strong", "Protect your account");
      add(box, "p", "Hospital staff and support will never ask for your password or verification code by email, phone, or message. Never share them.");
    }

    function logs(parent) {
      const section = add(parent, "section", undefined, "logs");
      add(section, "h2", "Logs");
      add(section, "p", "Local testing events are mirrored here and in the browser console.", "muted");
      const list = add(section, "div", "", "");
      list.id = "log-list";
    }

    function form(parent, onSubmit) {
      const f = document.createElement("form");
      f.noValidate = true;
      f.addEventListener("submit", async event => {
        event.preventDefault();
        await onSubmit(f);
      });
      parent.appendChild(f);
      return f;
    }

    function input(parent, labelText, type, name, autocomplete) {
      const label = el("label", labelText);
      const field = document.createElement("input");
      field.type = type;
      field.name = name;
      field.autocomplete = autocomplete;
      field.required = true;
      label.appendChild(field);
      parent.appendChild(label);
      return field;
    }

    function submit(parent, text) {
      const button = el("button", text);
      button.type = "submit";
      parent.appendChild(button);
      return button;
    }

    function renderRecovery(root) {
      add(root, "h2", "Reset your password");
      add(root, "p", "Enter your account email address or account identifier. For privacy, this service gives the same response whether or not an account is available.");
      const f = form(root, async () => {
        const result = await api("/api/recovery/request", { identifier: identifier.value });
        status.textContent = result.message || "We could not complete that request.";
        status.className = "notice " + (result.ok ? "success" : "error");
        if (result.ok && result.mockDeliveryToken) {
          log("Mock recovery delivery token: " + result.mockDeliveryToken);
          log("Mock recovery link: " + result.mockRecoveryLink);
          linkButton.hidden = false;
          linkButton.onclick = () => go("verify", result.mockDeliveryToken);
        }
      });
      const identifier = input(f, "Account email or identifier", "text", "identifier", "username");
      identifier.maxLength = 254;
      submit(f, "Request secure recovery");
      const status = add(root, "div", "", "notice");
      status.hidden = true;
      const linkButton = el("button", "Open simulated recovery link", "secondary");
      linkButton.type = "button";
      linkButton.className = "secondary";
      linkButton.hidden = true;
      root.appendChild(linkButton);
      guidance(root);
    }

    function renderVerify(root) {
      add(root, "h2", "Verify recovery code");
      add(root, "p", "Use the code from the secure recovery message, or submit it manually below.");
      const f = form(root, async () => {
        const result = await api("/api/recovery/verify", { token: code.value });
        if (result.ok) {
          log("Recovery token verification succeeded.");
          go("reset");
        } else {
          status.textContent = result.message;
          status.className = "notice error";
        }
      });
      const code = input(f, "Recovery code", "text", "token", "one-time-code");
      code.maxLength = 128;
      const linkToken = new URLSearchParams(location.search).get("token");
      if (linkToken && /^[A-Za-z0-9_-]{20,128}$/.test(linkToken)) code.value = linkToken;
      submit(f, "Verify code");
      const status = add(root, "div", "", "notice");
      status.hidden = false;
      const back = el("button", "Request another code");
      back.type = "button";
      back.className = "secondary";
      back.onclick = () => go("recovery");
      root.appendChild(back);
      guidance(root);
    }

    function renderReset(root) {
      add(root, "h2", "Choose a strong password");
      add(root, "p", "Use at least 12 characters, including uppercase and lowercase letters, a number, and a symbol.");
      const f = form(root, async () => {
        if (password.value !== confirm.value) {
          status.textContent = "The passwords do not match.";
          status.className = "notice error";
          return;
        }
        const result = await api("/api/recovery/reset-password", { password: password.value });
        password.value = "";
        confirm.value = "";
        if (result.ok) {
          log("Mock MFA verification code: " + result.mockMfaCode);
          go("mfa");
        } else {
          status.textContent = result.message;
          status.className = "notice error";
        }
      });
      const password = input(f, "New password", "password", "password", "new-password");
      password.maxLength = 128;
      const confirm = input(f, "Confirm new password", "password", "confirm", "new-password");
      confirm.maxLength = 128;
      submit(f, "Save password securely");
      const status = add(root, "div", "", "notice");
      status.hidden = false;
      guidance(root);
    }

    function renderMfa(root) {
      add(root, "h2", "Complete verification");
      add(root, "p", "Enter the verification code from your secure authentication method.");
      const f = form(root, async () => {
        const result = await api("/api/mfa/verify", { code: code.value });
        code.value = "";
        if (result.ok) {
          log("Mock MFA verification succeeded.");
          go("privacy");
        } else {
          status.textContent = result.message;
          status.className = "notice error";
        }
      });
      const code = input(f, "Verification code", "text", "code", "one-time-code");
      code.inputMode = "numeric";
      code.maxLength = 12;
      submit(f, "Confirm code");
      const status = add(root, "div", "", "notice");
      status.hidden = false;
      guidance(root);
    }

    function renderPrivacy(root) {
      add(root, "h2", "Updated privacy conditions");
      add(root, "p", "Before an appointment can be requested, please review and accept the updated privacy conditions.");
      const list = el("ul");
      ["Your account is protected by secure sign-in.", "Only necessary information is used to process appointment requests.", "You can contact the hospital through established channels for privacy questions."].forEach(item => add(list, "li", item));
      root.appendChild(list);
      const accept = el("button", "I accept the privacy conditions");
      accept.type = "button";
      accept.onclick = async () => {
        const result = await api("/api/privacy/accept", {});
        if (result.ok) {
          log("Privacy conditions accepted in authenticated session.");
          go("appointment");
        } else {
          message(root, result.message, "error");
        }
      };
      root.appendChild(accept);
      guidance(root);
    }

    function renderAppointment(root) {
      add(root, "h2", "Appointment request");
      add(root, "p", "Your privacy conditions have been accepted. You may now confirm a medication review appointment request.");
      const confirm = el("button", "Confirm appointment request");
      confirm.type = "button";
      confirm.onclick = async () => {
        const result = await api("/api/appointment/confirm", {});
        if (result.ok) {
          log("Protected appointment request confirmed.");
          go("confirmed");
        } else {
          message(root, result.message, "error");
        }
      };
      root.appendChild(confirm);
      guidance(root);
    }

    function renderConfirmed(root) {
      add(root, "h2", "Appointment request confirmed");
      message(root, "Your medication review appointment request has been recorded. Hospital staff will follow the established contact process.", "success");
      add(root, "p", "No personal health record or patient identifier is shown in this confirmation.");
      guidance(root);
    }

    function render() {
      app.replaceChildren();
      const root = el("section");
      app.appendChild(root);

      let view = safeView();
      if (view === "reset" && !session.resetAuthorized) view = "recovery";
      if (view === "mfa" && !session.mfaPending) view = "recovery";
      if ((view === "privacy" || view === "appointment" || view === "confirmed") && !session.authenticated) view = "recovery";
      if (view === "appointment" && !session.privacyAccepted) view = "privacy";
      if (view === "confirmed" && !session.appointmentConfirmed) view = "appointment";

      if (view === "verify") renderVerify(root);
      else if (view === "reset") renderReset(root);
      else if (view === "mfa") renderMfa(root);
      else if (view === "privacy") renderPrivacy(root);
      else if (view === "appointment") renderAppointment(root);
      else if (view === "confirmed") renderConfirmed(root);
      else renderRecovery(root);
      logs(root);
    }

    window.addEventListener("popstate", render);
    api("/api/session").then(data => {
      if (!data.ok) throw new Error("session unavailable");
      csrf = data.csrf;
      session = data;
      render();
    }).catch(() => {
      app.replaceChildren();
      add(app, "p", "The secure service is temporarily unavailable. Please try again later.", "notice error");
    });
  })();
  </script>
</body>
</html>`;
}

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";

/*
  Requirement 3: only a TLS listener is created. Plain HTTP cannot reach this handler;
  additionally, any request not represented as HTTPS is rejected without redirect data.
*/
Bun.serve({
  hostname: "localhost",
  port: 3000,
  tls: {
    cert: Bun.file(certPath),
    key: Bun.file(keyPath),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (url.protocol !== "https:") {
        return new Response("HTTPS is required.", { status: 400, headers: { "Cache-Control": "no-store" } });
      }

      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, url);
      }

      if (request.method === "GET" && url.pathname === "/") {
        const sessionInfo = sessionFor(request);
        const scriptNonce = nonce();
        const headers = securityHeaders(scriptNonce);
        if (sessionInfo.newCookie) headers.append("Set-Cookie", sessionInfo.newCookie);
        return new Response(pageHtml(scriptNonce), { status: 200, headers });
      }

      return new Response("Not found.", {
        status: 404,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    } catch {
      /* Requirement 3: no stack traces or debug details are exposed. */
      return new Response("Service unavailable.", {
        status: 500,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
  },
});

console.log("Secure recovery demo listening at https://localhost:3000");
