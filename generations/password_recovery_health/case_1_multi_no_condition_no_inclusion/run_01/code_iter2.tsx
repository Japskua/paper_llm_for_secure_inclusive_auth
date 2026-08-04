
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System — single-file Bun TLS server + vanilla HTML SPA.

  Requirement 1: session-bound CSRF and state checks on every sensitive action.
  Requirement 2: client renders all text through textContent; no input is inserted as HTML.
  Requirement 3: TLS-only startup, secure headers, random expiring single-use tokens.
  Requirement 4: bcrypt password hashing, shared throttling, ownership proof, MFA.
  Requirement 5: fixed local navigation and visible anti-phishing guidance.
*/

type ResetRecord = {
  token: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  ownershipPending: boolean;
  ownershipProven: boolean;
  resetVerified: boolean;
  passwordUpdated: boolean;
  mfaComplete: boolean;
  privacyAccepted: boolean;
};

type ThrottleRecord = {
  attempts: number[];
  blockedUntil: number;
  touchedAt: number;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();
const sharedThrottle = new Map<string, ThrottleRecord>();

const SESSION_COOKIE = "__Host-hospital_recovery";
const SESSION_AGE_SECONDS = 30 * 60;
const RESET_AGE_MS = 10 * 60 * 1000;
const THROTTLE_MAX_RECORDS = 512;

const MOCK_MFA_CODE = "482913";
const MOCK_OWNERSHIP_PROOF = "ACADEMIC-PROOF-4821";

let mockPasswordHash = await Bun.password.hash("Initial-Demo-Password!9", {
  algorithm: "bcrypt",
  cost: 10,
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const cookies: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) {
      cookies[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
    }
  }
  return cookies;
}

function newSession(): Session {
  return {
    id: randomToken(),
    csrf: randomToken(),
    createdAt: Date.now(),
    ownershipPending: false,
    ownershipProven: false,
    resetVerified: false,
    passwordUpdated: false,
    mfaComplete: false,
    privacyAccepted: false,
  };
}

function sessionFor(request: Request, create = false): { session?: Session; isNew: boolean } {
  const sessionId = parseCookies(request)[SESSION_COOKIE];
  const existing = sessionId ? sessions.get(sessionId) : undefined;

  if (existing && Date.now() - existing.createdAt < SESSION_AGE_SECONDS * 1000) {
    return { session: existing, isNew: false };
  }

  if (!create) return { isNew: false };

  const session = newSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Max-Age=${SESSION_AGE_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

function nonce(): string {
  return randomToken(18);
}

function securityHeaders(scriptNonce: string, contentType = "text/html; charset=utf-8"): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy":
      `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; ` +
      `form-action 'self'; connect-src 'self'; img-src 'self'; style-src 'nonce-${scriptNonce}'; ` +
      `script-src 'nonce-${scriptNonce}'`,
  });
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function json(body: Record<string, unknown>, status = 200, setCookie?: string): Response {
  const headers = securityHeaders(nonce(), "application/json; charset=utf-8");
  if (setCookie) headers.set("Set-Cookie", setCookie);
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(status = 400): Response {
  return json({ ok: false, message: "We could not process that request. Please try again." }, status);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;

  const text = await request.text();
  if (text.length > 4096) return null;

  try {
    const data = JSON.parse(text);
    return data && typeof data === "object" && !Array.isArray(data)
      ? data as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Requirement 1: all state-changing endpoints require the unique session CSRF token. */
function csrfSession(request: Request, data: Record<string, unknown>): Session | null {
  const { session } = sessionFor(request);
  if (!session || typeof data.csrf !== "string") return null;
  return constantTimeEqual(session.csrf, data.csrf) ? session : null;
}

/*
  Requirement 4: shared throttle state is deliberately outside sessions.
  A newly created browser session cannot reset counters. Bun's Fetch Request
  does not expose peer sockets, so a strictly validated forwarding address is
  used when present; otherwise the bounded global fallback is used.
*/
function throttleScope(request: Request): string {
  const forwarded = (request.headers.get("x-forwarded-for") || "")
    .split(",")[0]
    .trim();

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(forwarded) || /^[0-9a-fA-F:]{2,45}$/.test(forwarded)) {
    return `client:${forwarded}`;
  }
  return "global-fallback";
}

function trimThrottleRecords(): void {
  if (sharedThrottle.size <= THROTTLE_MAX_RECORDS) return;
  const oldest = [...sharedThrottle.entries()]
    .sort((a, b) => a[1].touchedAt - b[1].touchedAt)
    .slice(0, sharedThrottle.size - THROTTLE_MAX_RECORDS);

  for (const [key] of oldest) sharedThrottle.delete(key);
}

function registerSharedAttempt(
  request: Request,
  action: string,
  limit: number,
  windowMs: number,
  blockMs: number,
): boolean {
  const now = Date.now();
  const key = `${action}:${throttleScope(request)}`;
  let record = sharedThrottle.get(key);

  if (!record) {
    record = { attempts: [], blockedUntil: 0, touchedAt: now };
    sharedThrottle.set(key, record);
    trimThrottleRecords();
  }

  record.touchedAt = now;
  record.attempts = record.attempts.filter((time) => now - time < windowMs);

  if (record.blockedUntil > now) return false;

  record.attempts.push(now);
  if (record.attempts.length >= limit) {
    record.attempts = [];
    record.blockedUntil = now + blockMs;
  }

  return true;
}

function isSharedBlocked(request: Request, action: string): boolean {
  const record = sharedThrottle.get(`${action}:${throttleScope(request)}`);
  return !!record && record.blockedUntil > Date.now();
}

function validPassword(password: string): string | null {
  if (password.length < 12 || password.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[^A-Za-z0-9]/.test(password)
  ) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}

/* Requirement 3: remove expired sensitive state and bounded rate-limit history. */
setInterval(() => {
  const now = Date.now();

  for (const [token, record] of resetTokens) {
    if (record.expiresAt < now || record.used) resetTokens.delete(token);
  }

  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_AGE_SECONDS * 1000) sessions.delete(id);
  }

  for (const [key, record] of sharedThrottle) {
    if (record.blockedUntil < now && now - record.touchedAt > 30 * 60_000) {
      sharedThrottle.delete(key);
    }
  }
}, 60_000).unref();

function page(scriptNonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Recovery</title>
  <style nonce="${scriptNonce}">
    :root { color-scheme:light; --navy:#12314a; --blue:#1769aa; --pale:#eef6fa; --line:#bfd0db; --red:#a12d2d; --green:#16683b; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; font:17px/1.55 Arial,Helvetica,sans-serif; color:#17242d; background:#f4f7f8; }
    header { background:var(--navy); color:white; padding:1.2rem; border-bottom:5px solid #4aa7bb; }
    header div, main, footer { max-width:760px; margin:auto; }
    h1 { margin:0; font-size:1.45rem; }
    h2 { margin-top:0; color:var(--navy); line-height:1.25; }
    h3 { color:var(--navy); font-size:1.05rem; }
    main { padding:2rem 1rem 1rem; }
    section.card { background:white; border:1px solid var(--line); border-radius:8px; padding:1.5rem; box-shadow:0 1px 2px #00000012; }
    label { display:block; margin:1rem 0 .3rem; font-weight:bold; }
    input { width:100%; padding:.7rem; border:2px solid #748896; border-radius:4px; font:inherit; }
    input:focus { outline:3px solid #87cce0; outline-offset:1px; }
    input[type="checkbox"] { width:auto; margin:.15rem .55rem 0 0; transform:scale(1.25); }
    .check-label { display:flex; align-items:flex-start; font-weight:normal; margin-top:1rem; }
    button { margin-top:1.25rem; padding:.75rem 1.1rem; border:0; border-radius:4px; background:var(--blue); color:white; font-size:1rem; font-weight:bold; cursor:pointer; }
    button:hover { background:#0c527f; }
    button:disabled { background:#70818b; cursor:wait; }
    .notice { margin:1rem 0; padding:.8rem 1rem; border-left:5px solid #287da1; background:var(--pale); }
    .success { border-left-color:var(--green); background:#ebf8ef; }
    .error { border-left-color:var(--red); background:#fff0f0; color:#6c1717; }
    .conditions { padding:1rem; border:1px solid var(--line); border-radius:4px; background:#f8fbfc; }
    .guidance { margin-top:1.5rem; padding-top:1rem; border-top:1px solid var(--line); font-size:.96rem; }
    .guidance strong { color:var(--navy); }
    .small { color:#43545e; font-size:.92rem; }
    #logs { max-height:180px; overflow:auto; padding:.8rem; border-radius:4px; background:#10232d; color:#d9f5e4; white-space:pre-wrap; font:13px/1.4 ui-monospace,monospace; }
    footer { padding:1rem; color:#42535d; font-size:.9rem; }
  </style>
</head>
<body>
<header><div><h1>Hospital Account Portal</h1></div></header>
<main>
  <div id="app" aria-live="polite">Loading secure recovery…</div>
  <section aria-label="Mock operation logs">
    <h2>Logs</h2>
    <p class="small">Academic simulation activity shown from the browser console.</p>
    <pre id="logs">Ready.</pre>
  </section>
</main>
<footer>Verified localhost portal · Secure password recovery demonstration</footer>
<script nonce="${scriptNonce}">
(() => {
  "use strict";

  let csrf = "";
  const app = document.getElementById("app");
  const logs = document.getElementById("logs");

  // Requirements 2 and 5: DOM APIs and fixed same-origin paths only.
  function el(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function logMock(event, details) {
    console.log("[Hospital recovery mock]", event, details);
    const line = event + " " + JSON.stringify(details);
    logs.textContent = logs.textContent === "Ready." ? line : logs.textContent + "\\n" + line;
    logs.scrollTop = logs.scrollHeight;
  }

  function card(title) {
    const section = el("section");
    section.className = "card";
    section.append(el("h2", title));
    return section;
  }

  function notice(text, kind) {
    const box = el("p", text);
    box.className = "notice" + (kind ? " " + kind : "");
    return box;
  }

  function guidance() {
    const aside = el("aside");
    aside.className = "guidance";
    aside.append(el("strong", "Protect your account: "));
    aside.append(document.createTextNode(
      "Hospital staff never ask for your password or verification codes by email or phone. Use only this verified localhost portal. Never forward a recovery link or code."
    ));
    return aside;
  }

  function input(form, labelText, type, name, autocomplete) {
    const label = el("label", labelText);
    label.htmlFor = name;
    const field = document.createElement("input");
    field.type = type;
    field.id = name;
    field.name = name;
    field.autocomplete = autocomplete || "off";
    field.required = true;
    form.append(label, field);
    return field;
  }

  async function api(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "HospitalRecovery" },
      body: JSON.stringify(Object.assign({}, data, { csrf: csrf }))
    });
    const payload = await response.json().catch(() => ({
      ok: false,
      message: "A secure response could not be read."
    }));
    return { response, payload };
  }

  function showRequest(message) {
    const section = card("Reset your password");
    section.append(el("p", "Enter a non-identifying academic test identifier. The same response is returned for every submitted identifier."));
    if (message) section.append(notice(message, "success"));

    const form = document.createElement("form");
    const identifier = input(form, "Academic test identifier", "text", "academic-identifier", "username");
    identifier.maxLength = 100;
    identifier.placeholder = "Example: academic-test-user";

    const submit = el("button", "Continue to ownership proof");
    submit.type = "submit";
    const feedback = el("div");
    feedback.setAttribute("role", "status");
    form.append(submit, feedback);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const result = await api("/api/request-reset", { identifier: identifier.value });
      submit.disabled = false;

      feedback.replaceChildren(notice(
        result.payload.message || "If eligible, continue with account ownership proof.",
        "success"
      ));

      if (result.payload.ok) {
        logMock("Reset request accepted with privacy-preserving response", { next: "ownership-proof" });
        setTimeout(showOwnershipProof, 250);
      }
    });

    section.append(form, guidance());
    app.replaceChildren(section);
  }

  function showOwnershipProof(message) {
    const section = card("Prove account ownership");
    section.append(el("p", "Before recovery instructions are issued, complete the simulated academic account-ownership proof."));
    section.append(el("p", "Testing proof value: ACADEMIC-PROOF-4821"));
    logMock("Ownership proof challenge simulated", { proof: "ACADEMIC-PROOF-4821" });

    if (message) section.append(notice(message, "error"));

    const form = document.createElement("form");
    const proof = input(form, "Ownership proof", "text", "ownership-proof", "one-time-code");
    proof.maxLength = 64;

    const submit = el("button", "Verify ownership");
    submit.type = "submit";
    form.append(submit);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const result = await api("/api/prove-ownership", { proof: proof.value.trim() });
      submit.disabled = false;

      if (result.payload.ok && result.payload.delivery) {
        logMock("Reset delivery simulated", result.payload.delivery);
        showCode("A simulated recovery link and code have been delivered. They are visible in the Logs panel for this academic test.");
      } else {
        showOwnershipProof(result.payload.message || "The ownership proof cannot be verified.");
      }
    });

    section.append(form, guidance());
    app.replaceChildren(section);
  }

  function showCode(message) {
    const section = card("Verify recovery code");
    section.append(el("p", "Open the simulated recovery link in this same browser, or enter the recovery code manually."));
    if (message) section.append(notice(message, message.includes("delivered") ? "success" : "error"));

    const form = document.createElement("form");
    const code = input(form, "Recovery code", "text", "recovery-code", "one-time-code");
    code.maxLength = 100;
    code.pattern = "[A-Za-z0-9_-]+";

    const submit = el("button", "Verify code");
    submit.type = "submit";
    form.append(submit);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const result = await api("/api/verify-token", { token: code.value.trim() });
      submit.disabled = false;

      if (result.payload.ok) showPassword();
      else showCode(result.payload.message || "This recovery code cannot be used.");
    });

    section.append(form, guidance());
    app.replaceChildren(section);
  }

  function showPassword() {
    const section = card("Choose a new password");
    section.append(el("p", "Use at least 12 characters, including uppercase, lowercase, a number, and a symbol."));

    const form = document.createElement("form");
    const password = input(form, "New password", "password", "new-password", "new-password");
    const confirmation = input(form, "Confirm new password", "password", "confirm-password", "new-password");

    const submit = el("button", "Update password");
    submit.type = "submit";
    const feedback = el("div");
    feedback.setAttribute("role", "alert");
    form.append(submit, feedback);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      if (password.value !== confirmation.value) {
        feedback.replaceChildren(notice("The passwords do not match.", "error"));
        return;
      }

      submit.disabled = true;
      const result = await api("/api/change-password", {
        password: password.value,
        confirmation: confirmation.value
      });
      submit.disabled = false;

      if (result.payload.ok) {
        logMock("MFA challenge simulated", {
          code: result.payload.mfaCode,
          purpose: "post-reset verification"
        });
        showMfa();
      } else {
        feedback.replaceChildren(notice(result.payload.message || "Password update could not be completed.", "error"));
      }
    });

    section.append(form, guidance());
    app.replaceChildren(section);
  }

  function showMfa(message) {
    const section = card("Confirm account security");
    section.append(el("p", "Enter the six-digit verification code from the simulated secure authenticator step."));
    if (message) section.append(notice(message, "error"));

    const form = document.createElement("form");
    const code = input(form, "Verification code", "text", "mfa-code", "one-time-code");
    code.inputMode = "numeric";
    code.maxLength = 6;
    code.pattern = "[0-9]{6}";

    const submit = el("button", "Confirm and continue");
    submit.type = "submit";
    form.append(submit);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const result = await api("/api/verify-mfa", { code: code.value.trim() });
      submit.disabled = false;

      if (result.payload.ok) showPrivacyConditions();
      else showMfa(result.payload.message || "That verification code cannot be used.");
    });

    section.append(form, guidance());
    app.replaceChildren(section);
  }

  function showPrivacyConditions(message) {
    const section = card("Updated privacy conditions");
    section.append(el("p", "Your password reset and security verification are complete. Review and affirmatively accept the updated conditions before appointment booking can continue."));
    if (message) section.append(notice(message, "error"));

    const conditions = el("div");
    conditions.className = "conditions";
    conditions.append(el("h3", "Privacy conditions"));
    conditions.append(el("p", "I understand that hospital authorities may process the minimum necessary account information to arrange my medication review appointment."));
    conditions.append(el("p", "I understand that I may withdraw this consent through the hospital's verified account support process."));

    const form = document.createElement("form");
    const label = el("label");
    label.className = "check-label";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.required = true;
    checkbox.id = "privacy-consent";
    label.htmlFor = "privacy-consent";
    label.append(checkbox, document.createTextNode(" I have read and accept the updated privacy conditions."));

    const submit = el("button", "Accept conditions and continue");
    submit.type = "submit";
    form.append(label, submit);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!checkbox.checked) {
        showPrivacyConditions("Please affirmatively check the consent box before continuing.");
        return;
      }

      submit.disabled = true;
      const result = await api("/api/accept-privacy", { accepted: true });
      submit.disabled = false;

      if (result.payload.ok) {
        logMock("Privacy conditions consent recorded", { accepted: true });
        showComplete();
      } else {
        showPrivacyConditions(result.payload.message || "Consent could not be recorded.");
      }
    });

    section.append(conditions, form, guidance());
    app.replaceChildren(section);
  }

  function showComplete() {
    const section = card("Appointment booking may continue");
    section.append(notice(
      "Your password has been reset, multi-factor verification is complete, and you accepted the updated privacy conditions. Hospital authorities may now continue appointment booking.",
      "success"
    ));
    section.append(el("p", "For your safety, do not share your new password or any verification code."));

    const button = el("button", "Return to recovery start");
    button.type = "button";
    button.addEventListener("click", () => {
      history.replaceState({}, "", "/");
      showRequest();
    });

    section.append(button);
    app.replaceChildren(section);
  }

  async function boot() {
    try {
      const response = await fetch("/api/session", { credentials: "same-origin" });
      const status = await response.json();
      csrf = typeof status.csrf === "string" ? status.csrf : "";

      const suppliedToken = new URLSearchParams(location.search).get("token");
      if (suppliedToken && /^[A-Za-z0-9_-]{20,100}$/.test(suppliedToken)) {
        history.replaceState({}, "", "/");
        const result = await api("/api/verify-token", { token: suppliedToken });
        if (result.payload.ok) showPassword();
        else showCode(result.payload.message || "This recovery link cannot be used.");
      } else if (status.privacyAccepted) {
        showComplete();
      } else if (status.mfaComplete) {
        showPrivacyConditions();
      } else if (status.passwordUpdated) {
        showMfa();
      } else if (status.resetVerified) {
        showPassword();
      } else if (status.ownershipPending && !status.ownershipProven) {
        showOwnershipProof();
      } else {
        showRequest();
      }
    } catch {
      app.replaceChildren(notice("The secure portal is temporarily unavailable. Please refresh and try again.", "error"));
    }
  }

  boot();
})();
</script>
</body>
</html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/session") {
    const result = sessionFor(request, true);
    const session = result.session!;

    return json({
      ok: true,
      csrf: session.csrf,
      ownershipPending: session.ownershipPending,
      ownershipProven: session.ownershipProven,
      resetVerified: session.resetVerified,
      passwordUpdated: session.passwordUpdated,
      mfaComplete: session.mfaComplete,
      privacyAccepted: session.privacyAccepted,
    }, 200, result.isNew ? sessionCookie(session) : undefined);
  }

  /*
    Requirement 4: this response has exactly the same HTTP status, message,
    and JSON field shape for every submitted identifier. It contains no
    delivery data and therefore cannot disclose account existence.
  */
  if (request.method === "POST" && path === "/api/request-reset") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    // Deliberately do not inspect, store, or compare the supplied identifier.
    const allowed = registerSharedAttempt(request, "reset-request", 3, 15 * 60_000, 5 * 60_000);
    if (allowed) {
      session.ownershipPending = true;
      session.ownershipProven = false;
    }

    return json({
      ok: true,
      message: "If eligible, continue with account ownership proof.",
      next: "ownership-proof",
    });
  }

  /*
    Requirement 4: a simulated ownership proof is required before any reset
    token is minted. The proof itself is a non-identifying academic test value.
  */
  if (request.method === "POST" && path === "/api/prove-ownership") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session || !session.ownershipPending || session.ownershipProven) return genericError(403);

    const proof = typeof data.proof === "string" ? data.proof : "";
    if (!constantTimeEqual(proof, MOCK_OWNERSHIP_PROOF)) {
      return json({ ok: false, message: "The ownership proof cannot be verified." });
    }

    session.ownershipProven = true;

    /* Requirement 3: random, session-bound, short-lived, single-use token. */
    const token = randomToken(32);
    resetTokens.set(token, {
      token,
      sessionId: session.id,
      expiresAt: Date.now() + RESET_AGE_MS,
      used: false,
    });

    // Academic-only simulated delivery returned only after successful proof.
    return json({
      ok: true,
      message: "Recovery instructions have been simulated.",
      delivery: {
        token,
        resetLink: `/reset?token=${token}`,
        expiresInMinutes: 10,
      },
    });
  }

  if (request.method === "POST" && path === "/api/verify-token") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    if (isSharedBlocked(request, "reset-token-failure")) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const now = Date.now();
    const token = typeof data.token === "string" ? data.token : "";
    const record = resetTokens.get(token);
    const valid =
      /^[A-Za-z0-9_-]{20,100}$/.test(token) &&
      !!record &&
      record.expiresAt >= now &&
      !record.used &&
      record.sessionId === session.id;

    if (!valid) {
      registerSharedAttempt(request, "reset-token-failure", 5, 10 * 60_000, 5 * 60_000);
      return json({ ok: false, message: "This recovery code cannot be verified." });
    }

    record!.used = true;
    session.resetVerified = true;
    return json({ ok: true });
  }

  if (request.method === "POST" && path === "/api/change-password") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session) return genericError(403);
    if (!session.resetVerified || session.passwordUpdated) return genericError(403);

    const password = typeof data.password === "string" ? data.password : "";
    const confirmation = typeof data.confirmation === "string" ? data.confirmation : "";

    if (password !== confirmation) {
      return json({ ok: false, message: "The passwords do not match." });
    }

    const policyError = validPassword(password);
    if (policyError) return json({ ok: false, message: policyError });

    /* Requirement 4: bcrypt hash only; plaintext is not persisted. */
    mockPasswordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    session.passwordUpdated = true;

    return json({ ok: true, mfaCode: MOCK_MFA_CODE });
  }

  if (request.method === "POST" && path === "/api/verify-mfa") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session) return genericError(403);
    if (!session.passwordUpdated) return genericError(403);

    if (isSharedBlocked(request, "mfa-failure")) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const code = typeof data.code === "string" ? data.code : "";
    if (!constantTimeEqual(code, MOCK_MFA_CODE)) {
      registerSharedAttempt(request, "mfa-failure", 5, 10 * 60_000, 5 * 60_000);
      return json({ ok: false, message: "That verification code cannot be verified." });
    }

    session.mfaComplete = true;
    return json({ ok: true });
  }

  /*
    Requirement 1 and new privacy-consent requirement:
    consent is CSRF protected, session scoped, and unavailable before MFA.
  */
  if (request.method === "POST" && path === "/api/accept-privacy") {
    const data = await requestBody(request);
    if (!data) return genericError();

    const session = csrfSession(request, data);
    if (!session || !session.mfaComplete) return genericError(403);
    if (data.accepted !== true) {
      return json({ ok: false, message: "Affirmative consent is required before continuing." });
    }

    session.privacyAccepted = true;
    return json({ ok: true });
  }

  // Requirement 5: fixed SPA-only local routes; no user destination is followed.
  if (request.method === "GET" && (path === "/" || path === "/reset")) {
    const result = sessionFor(request, true);
    const scriptNonce = nonce();
    const headers = securityHeaders(scriptNonce);

    if (result.isNew) headers.set("Set-Cookie", sessionCookie(result.session!));
    return new Response(page(scriptNonce), { status: 200, headers });
  }

  return new Response("Not found", {
    status: 404,
    headers: securityHeaders(nonce(), "text/plain; charset=utf-8"),
  });
}

async function safeFetch(request: Request): Promise<Response> {
  try {
    return await handle(request);
  } catch {
    // Requirement 3: no debug details, stack traces, or sensitive data are exposed.
    return new Response("The secure portal is temporarily unavailable.", {
      status: 500,
      headers: securityHeaders(nonce(), "text/plain; charset=utf-8"),
    });
  }
}

/*
  Requirement 3: TLS is mandatory. If either configured certificate is absent
  or unreadable, no recovery or redirect listener is started.
*/
const port = Number(Bun.env.PORT || 3000);
const httpPort = Number(Bun.env.HTTP_PORT || 8080);
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");

let certificate: string;
let privateKey: string;

try {
  if (!(await certFile.exists()) || !(await keyFile.exists())) {
    throw new Error("missing TLS material");
  }
  certificate = await certFile.text();
  privateKey = await keyFile.text();
  if (!certificate || !privateKey) throw new Error("empty TLS material");
} catch {
  console.error("Configuration error.");
  process.exit(1);
}

Bun.serve({
  port,
  tls: {
    cert: certificate!,
    key: privateKey!,
  },
  fetch: safeFetch,
});

/*
  The HTTP listener starts only after TLS starts and redirects solely to the
  fixed verified localhost HTTPS origin, never to a caller-provided host.
*/
Bun.serve({
  port: httpPort,
  fetch(request) {
    const requestUrl = new URL(request.url);
    return Response.redirect(
      `https://localhost:${port}${requestUrl.pathname}${requestUrl.search}`,
      308,
    );
  },
});
