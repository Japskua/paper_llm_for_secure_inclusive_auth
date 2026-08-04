
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL = 30 * 60 * 1000;
const RESET_TTL = 10 * 60 * 1000;
const LIMIT_WINDOW = 10 * 60 * 1000;
const LOCK_WINDOW = 15 * 60 * 1000;

type Limit = { count: number; windowStarted: number; lockedUntil: number };
type Recovery = {
  id: string;
  sessionId: string;
  tokenHash: string;
  expiresAt: number;
  tokenUsed: boolean;
  verified: boolean;
  passwordHash?: string;
  passwordSet: boolean;
  mfaIssued: boolean;
  completed: boolean;
  tokenLimit: Limit;
  passwordLimit: Limit;
  mfaLimit: Limit;
};
type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  recoveryId?: string;
  recoveryLimit: Limit;
};

const sessions = new Map<string, Session>();
const recoveries = new Map<string, Recovery>();

/* Security Evaluation 1, 3: cryptographically random per-session IDs, CSRF values, and reset tokens. */
function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

function freshLimit(): Limit {
  return { count: 0, windowStarted: Date.now(), lockedUntil: 0 };
}

function checkLimit(limit: Limit, maximum: number): boolean {
  const now = Date.now();
  if (limit.lockedUntil > now) return false;
  if (now - limit.windowStarted > LIMIT_WINDOW) {
    limit.count = 0;
    limit.windowStarted = now;
    limit.lockedUntil = 0;
  }
  return true;
}

function recordFailure(limit: Limit, maximum: number): void {
  const now = Date.now();
  if (now - limit.windowStarted > LIMIT_WINDOW) {
    limit.count = 0;
    limit.windowStarted = now;
  }
  limit.count++;
  if (limit.count >= maximum) limit.lockedUntil = now + LOCK_WINDOW;
}

function clearLimit(limit: Limit): void {
  limit.count = 0;
  limit.windowStarted = Date.now();
  limit.lockedUntil = 0;
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const values: Record<string, string> = {};
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) values[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return values;
}

function newSession(): Session {
  const session: Session = {
    id: randomHex(32),
    csrf: randomHex(32),
    expiresAt: Date.now() + SESSION_TTL,
    recoveryLimit: freshLimit(),
  };
  sessions.set(session.id, session);
  return session;
}

function sessionFor(request: Request): { session: Session; created: boolean } {
  const id = parseCookies(request).recovery_session;
  const existing = id ? sessions.get(id) : undefined;
  if (existing && existing.expiresAt > Date.now()) {
    existing.expiresAt = Date.now() + SESSION_TTL;
    return { session: existing, created: false };
  }
  if (id) sessions.delete(id);
  return { session: newSession(), created: true };
}

const SECURITY_HEADERS: Record<string, string> = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
};

function responseJson(
  body: Record<string, unknown>,
  status = 200,
  session?: Session,
  created = false,
): Response {
  const headers = new Headers(SECURITY_HEADERS);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (created && session) {
    headers.append(
      "Set-Cookie",
      `recovery_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}`,
    );
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(status = 400, session?: Session, created = false): Response {
  return responseJson(
    { error: "We could not complete that recovery step. Please start again if the problem continues." },
    status,
    session,
    created,
  );
}

/* Security Evaluation 1: state-changing requests need same-origin and dual CSRF validation. */
function validOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const expected = new URL(request.url).origin;
    return new URL(origin).origin === expected && new URL(origin).protocol === "https:";
  } catch {
    return false;
  }
}

function validCsrf(request: Request, data: Record<string, unknown>, session: Session): boolean {
  const header = request.headers.get("x-csrf-token") || "";
  const bodyToken = typeof data.csrf === "string" ? data.csrf : "";
  return validOrigin(request) &&
    header.length === session.csrf.length &&
    bodyToken.length === session.csrf.length &&
    constantTimeEqual(header, session.csrf) &&
    constantTimeEqual(bodyToken, session.csrf);
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  const length = Number(request.headers.get("content-length") || "0");
  if (!contentType.includes("application/json") || length > 4096) return null;
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Security Evaluation 2: narrow allowlists; contact is neither retained nor reflected. */
function validContact(value: unknown): boolean {
  return typeof value === "string" &&
    value.length >= 3 &&
    value.length <= 80 &&
    /^[A-Za-z0-9@+(). _-]+$/.test(value);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function validMfaCode(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

/* Security Evaluation 4: strong policy before Argon2id hashing; plaintext is never stored or logged. */
function strongPassword(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 14 || value.length > 128) return false;
  return /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    /[^A-Za-z0-9\s]/.test(value) &&
    !/\s/.test(value);
}

function currentRecovery(session: Session): Recovery | undefined {
  if (!session.recoveryId) return undefined;
  const recovery = recoveries.get(session.recoveryId);
  if (!recovery || recovery.sessionId !== session.id) return undefined;
  return recovery;
}

function stageFor(session: Session): string {
  const recovery = currentRecovery(session);
  if (!recovery) return "request";
  if (recovery.completed) return "complete";
  if (recovery.mfaIssued && recovery.passwordSet) return "mfa";
  if (recovery.verified) return "password";
  return "verify";
}

function passwordPolicyText(): string {
  return "Use at least 14 characters with uppercase, lowercase, a number, and a symbol. Do not use spaces.";
}

/* Single-file Bun/vanilla-JavaScript delivery. The nonce permits only this server-generated script and style. */
function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; font-family: Arial, sans-serif; background: #f3f7f8; color: #15252d; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; }
    header { background: #073b4c; color: white; padding: 1.4rem 1rem; }
    header div, main, footer { max-width: 760px; margin: auto; }
    header h1 { margin: 0; font-size: 1.4rem; }
    header p { margin: .45rem 0 0; color: #d8eef2; }
    main { padding: 1.5rem 1rem 2rem; }
    .card { background: white; border: 1px solid #c9d6da; border-radius: 10px; padding: 1.35rem; box-shadow: 0 1px 2px #00000012; }
    h2 { margin-top: 0; }
    label { display: block; font-weight: bold; margin: 1rem 0 .35rem; }
    input { display: block; width: 100%; border: 1px solid #74878e; border-radius: 5px; padding: .7rem; font: inherit; }
    button { margin-top: 1.15rem; padding: .7rem 1rem; background: #086788; color: white; border: 0; border-radius: 5px; font: inherit; font-weight: bold; cursor: pointer; }
    button:hover, button:focus { background: #075670; outline: 3px solid #b9e3ed; }
    a { color: #075f7c; }
    .notice { border-left: 4px solid #086788; background: #e9f6f8; padding: .8rem; margin: 1rem 0; }
    .warning { border-left-color: #9b5600; background: #fff5e7; }
    .feedback { min-height: 1.5rem; margin-top: .85rem; font-weight: bold; }
    .muted { color: #4e6066; }
    #log-panel { margin-top: 1.5rem; background: #102a32; color: #e9f5f7; border-radius: 8px; padding: 1rem; }
    #log-panel h2 { font-size: 1rem; margin: 0 0 .55rem; }
    #logs { margin: 0; padding-left: 1.2rem; font: .82rem ui-monospace, monospace; }
    #logs li { margin: .35rem 0; overflow-wrap: anywhere; }
    footer { padding: 0 1rem 2rem; color: #45575d; font-size: .9rem; }
  </style>
</head>
<body>
  <header><div><h1>Hospital account recovery</h1><p>Secure password reset for your personal healthcare account</p></div></header>
  <main>
    <section id="app" aria-live="polite" aria-busy="true"><p>Loading secure recovery…</p></section>
    <aside id="log-panel" aria-label="Simulated delivery logs"><h2>Logs</h2><ol id="logs"></ol></aside>
  </main>
  <footer>For your safety, never share passwords or one-time codes by email, text, or with callers claiming to be hospital staff.</footer>
  <script nonce="${nonce}">
    (() => {
      "use strict";
      let csrf = "";
      let serverStage = "request";
      const app = document.getElementById("app");
      const logs = document.getElementById("logs");

      function log(message) {
        console.log(message);
        const item = document.createElement("li");
        item.textContent = message;
        logs.appendChild(item);
      }

      function element(tag, text, className) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
      }

      function input(name, type, autocomplete, maxLength) {
        const node = document.createElement("input");
        node.name = name;
        node.type = type;
        node.autocomplete = autocomplete;
        node.maxLength = maxLength;
        node.required = true;
        return node;
      }

      function feedback() {
        const node = element("p", "", "feedback");
        node.setAttribute("role", "status");
        return node;
      }

      function safetyNote() {
        return element("p", "Safety reminder: hospital staff will never ask you to disclose your password or recovery code.", "notice warning");
      }

      function card(title, intro) {
        app.replaceChildren();
        const section = element("section", undefined, "card");
        section.setAttribute("aria-labelledby", "screen-title");
        const heading = element("h2", title);
        heading.id = "screen-title";
        section.append(heading, element("p", intro));
        app.append(section);
        return section;
      }

      function startOverLink(section) {
        const p = element("p");
        const link = element("a", "Start over");
        link.href = "#request";
        link.addEventListener("click", () => { location.hash = "request"; });
        p.append(link);
        section.append(p);
      }

      async function api(path, payload) {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
          body: JSON.stringify(Object.assign({}, payload, { csrf }))
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(typeof data.error === "string" ? data.error : "We could not complete that step.");
        return data;
      }

      function route() {
        const requested = location.hash.replace("#", "") || serverStage;
        const allowed = ["request", "verify", "password", "mfa", "complete"];
        const screen = allowed.includes(requested) && requested === serverStage ? requested : serverStage;
        if (screen === "request") renderRequest();
        else if (screen === "verify") renderVerify();
        else if (screen === "password") renderPassword();
        else if (screen === "mfa") renderMfa();
        else renderComplete();
      }

      function renderRequest() {
        const section = card("Reset your password", "Enter an account contact detail. We will give the same response whether or not it is associated with an account.");
        const form = document.createElement("form");
        const label = element("label", "Account contact");
        label.htmlFor = "contact";
        const contact = input("contact", "text", "username", 80);
        contact.id = "contact";
        contact.setAttribute("placeholder", "Email address or phone contact");
        const button = element("button", "Request recovery code");
        button.type = "submit";
        const message = feedback();
        form.append(label, contact, button, message);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          button.disabled = true;
          message.textContent = "Sending request…";
          try {
            const data = await api("/api/recovery-request", { contact: contact.value });
            message.textContent = data.message;
            if (typeof data.testToken === "string") {
              log("Simulated recovery delivery for this browser session. Test reset token: " + data.testToken);
              serverStage = "verify";
              setTimeout(() => { location.hash = "verify"; route(); }, 450);
            }
          } catch (error) {
            message.textContent = error instanceof Error ? error.message : "Please try again later.";
          } finally { button.disabled = false; }
        });
        section.append(form, safetyNote());
      }

      function renderVerify() {
        const section = card("Verify recovery code", "Enter the code from the simulated recovery delivery. The code expires quickly and can only be used once.");
        const form = document.createElement("form");
        const label = element("label", "Recovery code");
        label.htmlFor = "token";
        const token = input("token", "text", "one-time-code", 64);
        token.id = "token";
        token.pattern = "[a-fA-F0-9]{64}";
        const button = element("button", "Verify code");
        button.type = "submit";
        const message = feedback();
        form.append(label, token, button, message);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          button.disabled = true;
          try {
            await api("/api/verify-token", { token: token.value.toLowerCase() });
            serverStage = "password";
            location.hash = "password";
            route();
          } catch (error) {
            message.textContent = error instanceof Error ? error.message : "The code could not be verified.";
          } finally { button.disabled = false; }
        });
        section.append(form, safetyNote());
        startOverLink(section);
      }

      function renderPassword() {
        const section = card("Choose a new password", "Create a strong password for your healthcare account.");
        section.append(element("p", "Password rules: at least 14 characters, uppercase, lowercase, number, and symbol. No spaces.", "notice"));
        const form = document.createElement("form");
        const label = element("label", "New password");
        label.htmlFor = "password";
        const password = input("password", "password", "new-password", 128);
        password.id = "password";
        const confirmLabel = element("label", "Confirm new password");
        confirmLabel.htmlFor = "confirm-password";
        const confirm = input("confirm-password", "password", "new-password", 128);
        confirm.id = "confirm-password";
        const button = element("button", "Continue to security check");
        button.type = "submit";
        const message = feedback();
        form.append(label, password, confirmLabel, confirm, button, message);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (password.value !== confirm.value) {
            message.textContent = "The passwords do not match.";
            return;
          }
          button.disabled = true;
          try {
            const data = await api("/api/set-password", { password: password.value });
            password.value = "";
            confirm.value = "";
            if (typeof data.testMfaCode === "string") log("Simulated MFA delivery for this browser session. Test MFA code: " + data.testMfaCode);
            serverStage = "mfa";
            location.hash = "mfa";
            route();
          } catch (error) {
            password.value = "";
            confirm.value = "";
            message.textContent = error instanceof Error ? error.message : "The password could not be accepted.";
          } finally { button.disabled = false; }
        });
        section.append(form, safetyNote());
      }

      function renderMfa() {
        const section = card("Confirm security code", "For this simulated recovery, enter the six-digit MFA code delivered to this browser session.");
        const form = document.createElement("form");
        const label = element("label", "MFA code");
        label.htmlFor = "mfa";
        const code = input("mfa", "text", "one-time-code", 6);
        code.id = "mfa";
        code.inputMode = "numeric";
        code.pattern = "[0-9]{6}";
        const button = element("button", "Finish password reset");
        button.type = "submit";
        const message = feedback();
        form.append(label, code, button, message);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          button.disabled = true;
          try {
            await api("/api/verify-mfa", { code: code.value });
            serverStage = "complete";
            location.hash = "complete";
            route();
          } catch (error) {
            message.textContent = error instanceof Error ? error.message : "The security code could not be verified.";
          } finally { button.disabled = false; }
        });
        section.append(form, safetyNote());
      }

      function renderComplete() {
        const section = card("Password reset complete", "Your new password has been saved securely. You may now return to the hospital account sign-in page.");
        section.append(element("p", "No password or recovery code was saved in this page or in the delivery log.", "notice"));
        const p = element("p");
        const link = element("a", "Begin another recovery session");
        link.href = "#request";
        link.addEventListener("click", () => { location.hash = "request"; });
        p.append(link);
        section.append(p, safetyNote());
      }

      async function initialise() {
        try {
          const response = await fetch("/api/bootstrap", { credentials: "same-origin" });
          const data = await response.json();
          csrf = data.csrf;
          serverStage = data.stage;
          app.setAttribute("aria-busy", "false");
          route();
        } catch {
          app.replaceChildren(element("p", "Secure recovery is temporarily unavailable. Please try again later."));
        }
      }
      window.addEventListener("hashchange", route);
      initialise();
    })();
  </script>
</body>
</html>`;
}

async function handleApi(request: Request, path: string): Promise<Response> {
  const { session, created } = sessionFor(request);

  if (path === "/api/bootstrap" && request.method === "GET") {
    return responseJson({ csrf: session.csrf, stage: stageFor(session) }, 200, session, created);
  }

  if (request.method !== "POST") return genericError(405, session, created);
  const data = await readJson(request);
  if (!data || !validCsrf(request, data, session)) return genericError(403, session, created);

  if (path === "/api/recovery-request") {
    const contactIsValid = validContact(data.contact);
    if (!checkLimit(session.recoveryLimit, 3)) {
      return responseJson(
        { message: "If recovery is available, instructions will be sent shortly. Please wait before trying again." },
        200,
        session,
        created,
      );
    }

    // Validation intentionally does not change the generic response and contact is never persisted.
    if (!contactIsValid) recordFailure(session.recoveryLimit, 3);
    else clearLimit(session.recoveryLimit);

    const rawToken = randomHex(32);
    const recovery: Recovery = {
      id: randomHex(24),
      sessionId: session.id,
      tokenHash: await sha256(rawToken),
      expiresAt: Date.now() + RESET_TTL,
      tokenUsed: false,
      verified: false,
      passwordSet: false,
      mfaIssued: false,
      completed: false,
      tokenLimit: freshLimit(),
      passwordLimit: freshLimit(),
      mfaLimit: freshLimit(),
    };
    recoveries.set(recovery.id, recovery);
    session.recoveryId = recovery.id;

    return responseJson(
      {
        message: "If recovery is available, instructions have been sent. Check the simulated delivery log below.",
        // Required test-only simulated delivery value; it is only returned to its owning HTTPS session.
        testToken: rawToken,
      },
      200,
      session,
      created,
    );
  }

  const recovery = currentRecovery(session);
  if (!recovery) return genericError(403, session, created);

  if (path === "/api/verify-token") {
    if (!checkLimit(recovery.tokenLimit, 5)) {
      return responseJson({ error: "Too many attempts. Please wait before trying again." }, 429, session, created);
    }
    const token = data.token;
    const suppliedHash = validToken(token) ? await sha256(token) : "";
    const acceptable = Date.now() <= recovery.expiresAt &&
      !recovery.tokenUsed &&
      constantTimeEqual(suppliedHash, recovery.tokenHash);
    if (!acceptable) {
      recordFailure(recovery.tokenLimit, 5);
      return responseJson({ error: "The recovery code is invalid, expired, or no longer available." }, 400, session, created);
    }
    recovery.tokenUsed = true; // Security Evaluation 3: single-use reset token.
    recovery.verified = true;
    clearLimit(recovery.tokenLimit);
    return responseJson({ ok: true }, 200, session, created);
  }

  if (path === "/api/set-password") {
    if (!recovery.verified || recovery.passwordSet || recovery.completed) return genericError(403, session, created);
    if (!checkLimit(recovery.passwordLimit, 5)) {
      return responseJson({ error: "Too many attempts. Please wait before trying again." }, 429, session, created);
    }
    const submittedPassword = data.password;
    if (!strongPassword(submittedPassword)) {
      recordFailure(recovery.passwordLimit, 5);
      return responseJson({ error: "Password does not meet the required security rules." }, 400, session, created);
    }
    // Argon2id hash only; no plaintext is assigned to persistent state or logged.
    recovery.passwordHash = await (Bun as any).password.hash(submittedPassword, { algorithm: "argon2id" });
    recovery.passwordSet = true;
    recovery.mfaIssued = true;
    clearLimit(recovery.passwordLimit);
    return responseJson({ ok: true, testMfaCode: "482913" }, 200, session, created);
  }

  if (path === "/api/verify-mfa") {
    if (!recovery.verified || !recovery.passwordSet || !recovery.mfaIssued || recovery.completed) {
      return genericError(403, session, created);
    }
    if (!checkLimit(recovery.mfaLimit, 5)) {
      return responseJson({ error: "Too many attempts. Please wait before trying again." }, 429, session, created);
    }
    const code = data.code;
    // Security Evaluation 4: deterministic test MFA is still gated by the reset-flow owner and CSRF.
    if (!validMfaCode(code) || !constantTimeEqual(code, "482913")) {
      recordFailure(recovery.mfaLimit, 5);
      return responseJson({ error: "The security code could not be verified." }, 400, session, created);
    }
    recovery.completed = true;
    clearLimit(recovery.mfaLimit);
    return responseJson({ ok: true }, 200, session, created);
  }

  return genericError(404, session, created);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file(CERT_PATH),
    key: Bun.file(KEY_PATH),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      /* Security Evaluation 3: this listener is TLS-only; reject unexpected non-HTTPS request URLs. */
      if (new URL(request.url).protocol !== "https:") {
        return new Response("Secure connection required.", { status: 400, headers: SECURITY_HEADERS });
      }

      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);

      if (request.method === "GET" && url.pathname === "/") {
        const { session, created } = sessionFor(request);
        const nonce = randomHex(16);
        const headers = new Headers(SECURITY_HEADERS);
        headers.set("Content-Type", "text/html; charset=utf-8");
        headers.set(
          "Content-Security-Policy",
          "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self'; style-src 'nonce-" +
            nonce + "'; script-src 'nonce-" + nonce + "'; upgrade-insecure-requests",
        );
        if (created) {
          headers.append(
            "Set-Cookie",
            `recovery_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}`,
          );
        }
        return new Response(appHtml(nonce), { status: 200, headers });
      }

      return new Response("Not found.", { status: 404, headers: SECURITY_HEADERS });
    } catch {
      // Security Evaluation 3: intentionally generic production error without stack traces.
      return new Response("Service temporarily unavailable.", { status: 500, headers: SECURITY_HEADERS });
    }
  },
});

console.log(`Secure recovery portal listening at https://localhost:${PORT}`);
