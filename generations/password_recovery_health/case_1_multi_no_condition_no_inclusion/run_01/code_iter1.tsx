
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System
  Single-file Bun server + SPA.
  Security requirement mappings:
  1: Session-bound CSRF, access checks, no identifiers in UI.
  2: DOM textContent rendering only; no user HTML is inserted.
  3: TLS, security headers, random expiring reset tokens.
  4: rate limits, bcrypt hashing, password policy, MFA.
  5: fixed local navigation and anti-phishing guidance.
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
  requestTimes: number[];
  verifyAttempts: number;
  verifyBlockedUntil: number;
  resetVerified: boolean;
  passwordUpdated: boolean;
  mfaAttempts: number;
  mfaBlockedUntil: number;
  mfaComplete: boolean;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();

const SESSION_COOKIE = "__Host-hospital_recovery";
const SESSION_AGE_SECONDS = 30 * 60;
const RESET_AGE_MS = 10 * 60 * 1000;
const MOCK_MFA_CODE = "482913";
const MOCK_ACCOUNT_EMAIL = "helena.patient@example.test"; // Never rendered or returned.

let mockPasswordHash = await Bun.password.hash("Initial-Demo-Password!9", {
  algorithm: "bcrypt",
  cost: 10,
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const pair of cookie.split(";")) {
    const separator = pair.indexOf("=");
    if (separator > 0) {
      result[pair.slice(0, separator).trim()] = pair.slice(separator + 1).trim();
    }
  }
  return result;
}

function newSession(): Session {
  return {
    id: randomToken(),
    csrf: randomToken(),
    createdAt: Date.now(),
    requestTimes: [],
    verifyAttempts: 0,
    verifyBlockedUntil: 0,
    resetVerified: false,
    passwordUpdated: false,
    mfaAttempts: 0,
    mfaBlockedUntil: 0,
    mfaComplete: false,
  };
}

function sessionFor(request: Request, create = false): { session?: Session; isNew: boolean } {
  const sid = parseCookies(request)[SESSION_COOKIE];
  const existing = sid ? sessions.get(sid) : undefined;
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
  const headers = new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
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
  return headers;
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function json(
  body: Record<string, unknown>,
  status = 200,
  setCookie?: string,
): Response {
  const n = nonce();
  const headers = securityHeaders(n, "application/json; charset=utf-8");
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
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Requirement 1: all state-changing API operations require the session CSRF secret. */
function csrfSession(request: Request, data: Record<string, unknown>): Session | null {
  const { session } = sessionFor(request);
  if (!session || typeof data.csrf !== "string") return null;
  return constantTimeEqual(session.csrf, data.csrf) ? session : null;
}

function validPassword(password: string): string | null {
  if (password.length < 12 || password.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) ||
      !/[^A-Za-z0-9]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}

/* Requirement 3: remove expired in-memory sensitive state. */
setInterval(() => {
  const now = Date.now();
  for (const [token, record] of resetTokens) {
    if (record.expiresAt < now || record.used) resetTokens.delete(token);
  }
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_AGE_SECONDS * 1000) sessions.delete(id);
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
    :root { color-scheme: light; --navy:#12314a; --blue:#1769aa; --pale:#eef6fa; --line:#bfd0db; --red:#a12d2d; --green:#16683b; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; font:17px/1.55 Arial, Helvetica, sans-serif; color:#17242d; background:#f4f7f8; }
    header { background:var(--navy); color:white; padding:1.2rem; border-bottom:5px solid #4aa7bb; }
    header div, main, footer { max-width:760px; margin:auto; }
    h1 { font-size:1.45rem; margin:0; } h2 { line-height:1.25; margin-top:0; color:var(--navy); }
    main { padding:2rem 1rem 1rem; }
    section.card { background:white; border:1px solid var(--line); border-radius:8px; padding:1.5rem; box-shadow:0 1px 2px #00000012; }
    label { display:block; font-weight:bold; margin:1rem 0 .3rem; }
    input { width:100%; padding:.7rem; border:2px solid #748896; border-radius:4px; font:inherit; }
    input:focus { outline:3px solid #87cce0; outline-offset:1px; }
    button { margin-top:1.25rem; background:var(--blue); color:white; border:0; border-radius:4px; padding:.75rem 1.1rem; font-weight:bold; font-size:1rem; cursor:pointer; }
    button:hover { background:#0c527f; } button:disabled { background:#70818b; cursor:wait; }
    .notice { background:var(--pale); border-left:5px solid #287da1; padding:.8rem 1rem; margin:1rem 0; }
    .success { background:#ebf8ef; border-left-color:var(--green); }
    .error { background:#fff0f0; border-left-color:var(--red); color:#6c1717; }
    .guidance { border-top:1px solid var(--line); margin-top:1.5rem; padding-top:1rem; font-size:.96rem; }
    .guidance strong { color:var(--navy); }
    .small { color:#43545e; font-size:.92rem; }
    #logs { max-height:160px; overflow:auto; white-space:pre-wrap; background:#10232d; color:#d9f5e4; padding:.8rem; border-radius:4px; font:13px/1.4 ui-monospace, monospace; }
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

  // Requirements 2 and 5: never use innerHTML or user-controlled navigation.
  function el(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function logMock(event, details) {
    console.log("[Hospital recovery mock]", event, details);
    const line = event + " " + JSON.stringify(details);
    logs.textContent = (logs.textContent === "Ready." ? "" : logs.textContent + "\\n") + line;
    logs.scrollTop = logs.scrollHeight;
  }
  function card(title) {
    const section = el("section"); section.className = "card";
    section.append(el("h2", title));
    return section;
  }
  function notice(text, type) {
    const box = el("p", text); box.className = "notice" + (type ? " " + type : "");
    return box;
  }
  function guidance() {
    const aside = el("aside"); aside.className = "guidance";
    aside.append(el("strong", "Protect your account: "));
    aside.append(document.createTextNode("Hospital staff never ask for your password or verification codes by email or phone. Use only this verified localhost portal. Never forward a recovery link or code."));
    return aside;
  }
  function input(form, labelText, type, name, autocomplete) {
    const label = el("label", labelText); label.htmlFor = name;
    const field = document.createElement("input");
    field.type = type; field.id = name; field.name = name; field.autocomplete = autocomplete || "off";
    field.required = true;
    form.append(label, field);
    return field;
  }
  async function api(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type":"application/json", "X-Requested-With":"HospitalRecovery"},
      body: JSON.stringify(Object.assign({}, data, {csrf}))
    });
    const payload = await response.json().catch(() => ({ok:false, message:"A secure response could not be read."}));
    return {response, payload};
  }
  function showRequest() {
    const section = card("Reset your password");
    section.append(el("p", "Enter the email used for your account. For privacy, the same response is shown whether or not an account can receive recovery instructions."));
    const form = document.createElement("form");
    const email = input(form, "Account email", "email", "email", "email");
    const submit = el("button", "Send recovery instructions"); submit.type = "submit";
    const feedback = el("div"); feedback.setAttribute("role", "status");
    form.append(submit, feedback);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled = true;
      const result = await api("/api/request-reset", {email:email.value});
      feedback.replaceChildren(notice(result.payload.message || "If eligible, recovery instructions have been sent.", "success"));
      if (result.payload.delivery) logMock("Reset delivery simulated", result.payload.delivery);
      submit.disabled = false;
    });
    section.append(form, guidance());
    app.replaceChildren(section);
  }
  function showCode(message) {
    const section = card("Verify recovery code");
    section.append(el("p", "Open your recovery link in this same browser, or enter the recovery code manually."));
    if (message) section.append(notice(message, "error"));
    const form = document.createElement("form");
    const code = input(form, "Recovery code", "text", "recovery-code", "one-time-code");
    code.maxLength = 100; code.pattern = "[A-Za-z0-9_-]+";
    const submit = el("button", "Verify code"); submit.type = "submit";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const result = await api("/api/verify-token", {token:code.value.trim()});
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
    const confirm = input(form, "Confirm new password", "password", "confirm-password", "new-password");
    const submit = el("button", "Update password"); submit.type = "submit";
    const feedback = el("div"); feedback.setAttribute("role", "alert");
    form.append(submit, feedback);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (password.value !== confirm.value) {
        feedback.replaceChildren(notice("The passwords do not match.", "error")); return;
      }
      submit.disabled = true;
      const result = await api("/api/change-password", {password:password.value, confirmation:confirm.value});
      submit.disabled = false;
      if (result.payload.ok) {
        logMock("MFA challenge simulated", {code:result.payload.mfaCode, purpose:"post-reset verification"});
        showMfa();
      } else feedback.replaceChildren(notice(result.payload.message || "Password update could not be completed.", "error"));
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
    code.inputMode = "numeric"; code.maxLength = 6; code.pattern = "[0-9]{6}";
    const submit = el("button", "Confirm and continue"); submit.type = "submit";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled = true;
      const result = await api("/api/verify-mfa", {code:code.value.trim()});
      submit.disabled = false;
      if (result.payload.ok) showComplete();
      else showMfa(result.payload.message || "That verification code cannot be used.");
    });
    section.append(guidance());
    app.replaceChildren(section);
  }
  function showComplete() {
    const section = card("Privacy conditions updated");
    section.append(notice("Your password has been reset, your account security check is complete, and the updated privacy conditions have been accepted. Hospital authorities may now continue appointment booking.", "success"));
    section.append(el("p", "For your safety, do not share your new password or any verification code."));
    const button = el("button", "Return to recovery start"); button.type = "button";
    button.addEventListener("click", () => { history.replaceState({}, "", "/"); showRequest(); });
    section.append(button);
    app.replaceChildren(section);
  }
  async function boot() {
    try {
      const response = await fetch("/api/session", {credentials:"same-origin"});
      const status = await response.json();
      csrf = status.csrf || "";
      const suppliedToken = new URLSearchParams(location.search).get("token");
      if (suppliedToken && /^[A-Za-z0-9_-]{20,100}$/.test(suppliedToken)) {
        history.replaceState({}, "", "/");
        const result = await api("/api/verify-token", {token:suppliedToken});
        if (result.payload.ok) showPassword();
        else showCode(result.payload.message || "This recovery link cannot be used.");
      } else if (status.complete) showComplete();
      else if (status.passwordUpdated) showMfa();
      else if (status.resetVerified) showPassword();
      else showRequest();
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
    return json({
      ok: true,
      csrf: result.session!.csrf,
      resetVerified: result.session!.resetVerified,
      passwordUpdated: result.session!.passwordUpdated,
      complete: result.session!.mfaComplete,
    }, 200, result.isNew ? sessionCookie(result.session!) : undefined);
  }

  if (request.method === "POST" && path === "/api/request-reset") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    const now = Date.now();
    session.requestTimes = session.requestTimes.filter((time) => now - time < 15 * 60_000);
    if (session.requestTimes.length >= 3) {
      return json({ ok: true, message: "If eligible, recovery instructions will be sent. Please wait before trying again." });
    }
    session.requestTimes.push(now);

    const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
    const response: Record<string, unknown> = {
      ok: true,
      message: "If eligible, recovery instructions have been sent. Check your secure recovery channel.",
    };

    /* Requirement 3: token is random, session-bound, expiring, and only minted for mock account. */
    if (email === MOCK_ACCOUNT_EMAIL) {
      const token = randomToken(32);
      resetTokens.set(token, { token, sessionId: session.id, expiresAt: now + RESET_AGE_MS, used: false });
      // This intentional academic-only delivery detail is consumed only by the browser's mock logger.
      response.delivery = { token, resetLink: `/reset?token=${token}`, expiresInMinutes: 10 };
    }
    return json(response);
  }

  if (request.method === "POST" && path === "/api/verify-token") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    const now = Date.now();
    if (session.verifyBlockedUntil > now) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }
    const token = typeof data.token === "string" ? data.token : "";
    const record = resetTokens.get(token);
    const valid = /^[A-Za-z0-9_-]{20,100}$/.test(token) && !!record &&
      record.expiresAt >= now && !record.used && record.sessionId === session.id;

    if (!valid) {
      session.verifyAttempts++;
      if (session.verifyAttempts >= 5) {
        session.verifyAttempts = 0;
        session.verifyBlockedUntil = now + 5 * 60_000;
      }
      return json({ ok: false, message: "This recovery code cannot be verified." });
    }

    record!.used = true; // single use
    session.resetVerified = true;
    session.verifyAttempts = 0;
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
    if (password !== confirmation) return json({ ok: false, message: "The passwords do not match." });
    const policyError = validPassword(password);
    if (policyError) return json({ ok: false, message: policyError });

    /* Requirement 4: bcrypt hash only; plaintext is never stored. */
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

    const now = Date.now();
    if (session.mfaBlockedUntil > now) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }
    const code = typeof data.code === "string" ? data.code : "";
    if (!constantTimeEqual(code, MOCK_MFA_CODE)) {
      session.mfaAttempts++;
      if (session.mfaAttempts >= 5) {
        session.mfaAttempts = 0;
        session.mfaBlockedUntil = now + 5 * 60_000;
      }
      return json({ ok: false, message: "That verification code cannot be verified." });
    }

    session.mfaComplete = true;
    session.mfaAttempts = 0;
    return json({ ok: true });
  }

  // Fixed SPA-only routes: no user-provided destination is ever followed.
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
    // Requirement 3: no stack traces or internal error details are exposed.
    return new Response("The secure portal is temporarily unavailable.", {
      status: 500,
      headers: securityHeaders(nonce(), "text/plain; charset=utf-8"),
    });
  }
}

const port = Number(Bun.env.PORT || 3000);
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");
const certificatesPresent = await certFile.exists() && await keyFile.exists();

if (certificatesPresent) {
  Bun.serve({
    port,
    tls: {
      cert: await certFile.text(),
      key: await keyFile.text(),
    },
    fetch: safeFetch,
  });

  // Requirement 3: companion HTTP listener redirects only to the fixed verified local HTTPS origin.
  Bun.serve({
    port: Number(Bun.env.HTTP_PORT || 8080),
    fetch(request) {
      const requestUrl = new URL(request.url);
      return Response.redirect(`https://localhost:${port}${requestUrl.pathname}${requestUrl.search}`, 308);
    },
  });
} else {
  // Certificate files are expected in certs/. This fallback keeps the single file runnable for local setup.
  Bun.serve({ port, fetch: safeFetch });
}
