
import { randomBytes } from "node:crypto";

/*
  Password Recovery Demonstration
  Security controls map to requirements:
  [1] Session ownership, CSRF, access control
  [2] Safe JSON handling and textContent-only client rendering
  [3] TLS, secure headers, opaque short-lived reset tokens
  [4] Password policy, Argon2id, MFA, throttling
  [5] No redirects/external URLs and anti-phishing guidance
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryAttempts: number[];
  verificationAttempts: number[];
  mfaAttempts: number[];
  authenticated: boolean;
  privacyAccepted: boolean;
};

type ResetRecord = {
  sessionId: string;
  expiresAt: number;
  used: boolean;
  verified: boolean;
  mfaComplete: boolean;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();
const SESSION_COOKIE = "hospital_recovery_session";
const RESET_TTL_MS = 10 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;
const RECOVERY_LIMIT = 4;
const VERIFY_LIMIT = 5;
const MFA_LIMIT = 5;
const MFA_TEST_CODE = "246810";

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
    }
  }
  return result;
}

function makeSession(): Session {
  return {
    id: randomToken(32),
    csrf: randomToken(32),
    createdAt: Date.now(),
    recoveryAttempts: [],
    verificationAttempts: [],
    mfaAttempts: [],
    authenticated: false,
    privacyAccepted: false,
  };
}

function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const id = parseCookies(request)[SESSION_COOKIE];
  const existing = id ? sessions.get(id) : undefined;
  if (existing) return { session: existing, isNew: false };
  const session = makeSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`;
}

function cleanOldState(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt > 30 * 60 * 1000) sessions.delete(id);
  }
  for (const [hash, record] of resetTokens) {
    if (record.expiresAt < now || record.used) resetTokens.delete(hash);
  }
}

function isThrottled(attempts: number[], limit: number): boolean {
  const now = Date.now();
  while (attempts.length && attempts[0] < now - WINDOW_MS) attempts.shift();
  return attempts.length >= limit;
}

function recordAttempt(attempts: number[]): void {
  attempts.push(Date.now());
}

function headers(nonce?: string): Headers {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  if (nonce) {
    h.set(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    );
  }
  return h;
}

function json(data: unknown, status = 200, extra?: Headers): Response {
  const h = extra || headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: h });
}

function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token");
  return !!supplied && supplied === session.csrf;
}

async function safeBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function safeEmail(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 254) return false;
  const email = value.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function strongPassword(value: unknown): { valid: boolean; message: string } {
  if (typeof value !== "string") return { valid: false, message: "Enter a new password." };
  if (value.length < 12) return { valid: false, message: "Use at least 12 characters." };
  if (value.length > 128) return { valid: false, message: "Password is too long." };
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return { valid: false, message: "Use upper-case, lower-case, number, and symbol characters." };
  }
  return { valid: true, message: "" };
}

function recordForToken(token: unknown, session: Session): ResetRecord | null {
  if (typeof token !== "string" || token.length < 20 || token.length > 200) return null;
  const record = resetTokens.get(sha256(token));
  if (!record || record.sessionId !== session.id || record.used || record.expiresAt < Date.now()) return null;
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
:root { color-scheme: light; --blue:#075b9d; --dark:#17324a; --line:#c8d5df; --soft:#eef6fa; --danger:#a61b1b; }
* { box-sizing:border-box; }
body { margin:0; font-family:Arial,Helvetica,sans-serif; background:#f5f8fa; color:#182b3b; line-height:1.5; }
header { background:var(--dark); color:white; padding:1rem; border-bottom:5px solid #2c94c9; }
header .wrap, main, footer { max-width:780px; margin:auto; }
header h1 { font-size:1.35rem; margin:0; }
header p { margin:.2rem 0 0; font-size:.92rem; }
main { padding:1.5rem 1rem 2rem; }
.card { background:white; padding:1.5rem; border:1px solid var(--line); border-radius:8px; box-shadow:0 1px 2px #00000012; }
h2 { margin-top:0; color:var(--dark); }
label { display:block; font-weight:bold; margin-top:1rem; }
input { width:100%; padding:.7rem; border:1px solid #70899b; border-radius:4px; font:inherit; }
button, .button-link { display:inline-block; background:var(--blue); color:white; border:0; border-radius:4px; padding:.72rem 1rem; font:inherit; font-weight:bold; cursor:pointer; margin-top:1.15rem; text-decoration:none; }
button:hover, .button-link:hover { background:#034777; }
button.secondary { background:#e7f0f5; color:#17324a; border:1px solid #8ea4b3; margin-left:.45rem; }
.notice { background:var(--soft); border-left:4px solid #2c94c9; padding:.8rem; margin:1rem 0; }
.error { color:var(--danger); font-weight:bold; min-height:1.5rem; margin:.75rem 0 0; }
.success { color:#176b35; font-weight:bold; }
.small { font-size:.9rem; }
.hidden { display:none !important; }
#logs { margin-top:1.5rem; background:#10212e; color:#d8eefc; border-radius:6px; padding:1rem; }
#logs h2 { color:white; font-size:1rem; margin:0 0 .5rem; }
#logList { margin:0; padding-left:1.25rem; font: .8rem ui-monospace, SFMono-Regular, Menlo, monospace; max-height:180px; overflow:auto; }
footer { padding:0 1rem 2rem; color:#4b5c69; font-size:.86rem; }
a { color:#075b9d; }
</style>
</head>
<body>
<header><div class="wrap"><h1>Hospital Account Portal</h1><p>Secure account recovery</p></div></header>
<main>
<section class="card" aria-labelledby="pageTitle">
<h2 id="pageTitle">Loading secure recovery</h2>
<div id="content" aria-live="polite"></div>
</section>
<section id="logs" aria-labelledby="logsTitle">
<h2 id="logsTitle">Logs</h2>
<ol id="logList"><li>Secure recovery page loaded.</li></ol>
</section>
</main>
<footer>
<strong>Stay safe:</strong> Hospital staff will never ask for your password, reset token, or verification code by email, phone, or support message. Enter codes only on this verified localhost portal.
</footer>
<script nonce="${nonce}">
(function () {
  "use strict";
  var csrf = "";
  var currentToken = "";
  var content = document.getElementById("content");
  var title = document.getElementById("pageTitle");
  var logList = document.getElementById("logList");

  function log(message) {
    console.log(message);
    var line = document.createElement("li");
    line.textContent = message;
    logList.appendChild(line);
    logList.scrollTop = logList.scrollHeight;
  }

  function el(tag, text) {
    var node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function clearPage(name) {
    title.textContent = name;
    content.replaceChildren();
  }

  function message(text, kind) {
    var node = el("p", text);
    node.className = kind || "error";
    node.setAttribute("role", "status");
    return node;
  }

  function button(text, type) {
    var node = el("button", text);
    node.type = type || "submit";
    return node;
  }

  function input(labelText, type, name, autocomplete) {
    var label = el("label", labelText);
    var field = document.createElement("input");
    field.type = type;
    field.name = name;
    field.required = true;
    if (autocomplete) field.autocomplete = autocomplete;
    label.appendChild(field);
    return { label: label, field: field };
  }

  async function api(path, body) {
    var response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(body || {})
    });
    var data;
    try { data = await response.json(); } catch (_) { data = { message: "Please try again." }; }
    return { ok: response.ok, data: data };
  }

  function route() {
    var params = new URLSearchParams(location.search);
    var requested = params.get("screen");
    var fromLink = params.get("token");
    if (requested === "verify" && fromLink && /^[A-Za-z0-9_-]{20,200}$/.test(fromLink)) {
      currentToken = fromLink;
      renderVerify();
      return;
    }
    if (location.hash === "#verify") { renderVerify(); return; }
    if (location.hash === "#privacy") { renderPrivacy(); return; }
    if (location.hash === "#success") { renderSuccess(); return; }
    renderRequest();
  }

  function renderRequest() {
    clearPage("Reset your password");
    var intro = el("p", "Enter the email address associated with your account. For privacy, the result is the same whether or not an account is found.");
    var note = el("div", "For this secure demonstration, a test reset token is logged below after a request. Do not share real reset tokens.", "notice");
    var form = document.createElement("form");
    var email = input("Account email", "email", "email", "email");
    var feedback = message("", "error");
    feedback.classList.add("hidden");
    form.append(email.label, button("Request reset"), feedback);
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      feedback.classList.add("hidden");
      var result = await api("/api/recovery/request", { email: email.field.value });
      feedback.textContent = result.data.message || "If the request can be processed, instructions are available.";
      feedback.className = result.ok ? "success" : "error";
      feedback.classList.remove("hidden");
      if (result.ok && result.data.testToken && result.data.resetLink) {
        log("SIMULATED RESET DELIVERY — test token: " + result.data.testToken);
        var link = document.createElement("a");
        link.className = "button-link";
        link.href = result.data.resetLink;
        link.textContent = "Open simulated reset link";
        form.appendChild(link);
      }
    });
    var manual = document.createElement("a");
    manual.href = "#verify";
    manual.textContent = "I already have a reset token";
    manual.className = "small";
    content.append(intro, note, form, el("p"), manual);
  }

  function renderVerify() {
    clearPage("Verify reset token");
    var info = el("p", "Paste the reset token from your simulated delivery, or use the simulated reset link.");
    var form = document.createElement("form");
    var token = input("Reset token", "text", "token", "one-time-code");
    token.field.value = currentToken;
    token.field.maxLength = 200;
    var feedback = message("", "error");
    feedback.classList.add("hidden");
    form.append(token.label, button("Verify token"), feedback);
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      var result = await api("/api/recovery/verify", { token: token.field.value.trim() });
      feedback.textContent = result.data.message || "We could not verify that token.";
      feedback.className = result.ok ? "success" : "error";
      feedback.classList.remove("hidden");
      if (result.ok) {
        currentToken = token.field.value.trim();
        log("SIMULATED MFA DELIVERY — verification code: " + result.data.mfaTestCode);
        setTimeout(renderMfa, 250);
      }
    });
    var back = document.createElement("a");
    back.href = "#request";
    back.textContent = "Back to recovery request";
    content.append(info, form, el("p"), back);
  }

  function renderMfa() {
    clearPage("Confirm your identity");
    var info = el("div", "A simulated verification code was delivered to this browser's console and Logs panel. In a real portal, this would be sent through a trusted enrolled method.", "notice");
    var form = document.createElement("form");
    var code = input("Verification code", "text", "code", "one-time-code");
    code.field.inputMode = "numeric";
    code.field.maxLength = 12;
    var feedback = message("", "error");
    feedback.classList.add("hidden");
    form.append(code.label, button("Confirm code"), feedback);
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      var result = await api("/api/recovery/mfa", { token: currentToken, code: code.field.value.trim() });
      feedback.textContent = result.data.message || "We could not confirm that code.";
      feedback.className = result.ok ? "success" : "error";
      feedback.classList.remove("hidden");
      if (result.ok) {
        log("MFA confirmation simulated successfully.");
        setTimeout(renderPassword, 250);
      }
    });
    content.append(info, form);
  }

  function renderPassword() {
    clearPage("Choose a new password");
    var policy = el("div", "Use at least 12 characters including upper-case and lower-case letters, a number, and a symbol. Never reuse a password from another service.", "notice");
    var form = document.createElement("form");
    var password = input("New password", "password", "password", "new-password");
    var confirm = input("Confirm new password", "password", "confirmPassword", "new-password");
    var feedback = message("", "error");
    feedback.classList.add("hidden");
    form.append(password.label, confirm.label, button("Save new password"), feedback);
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (password.field.value !== confirm.field.value) {
        feedback.textContent = "The password entries do not match.";
        feedback.className = "error";
        feedback.classList.remove("hidden");
        return;
      }
      var result = await api("/api/recovery/reset", { token: currentToken, password: password.field.value });
      feedback.textContent = result.data.message || "Password update could not be completed.";
      feedback.className = result.ok ? "success" : "error";
      feedback.classList.remove("hidden");
      if (result.ok) {
        password.field.value = "";
        confirm.field.value = "";
        currentToken = "";
        log("Password reset simulated successfully; reset token invalidated.");
        setTimeout(renderPrivacy, 250);
      }
    });
    content.append(policy, form);
  }

  function renderPrivacy() {
    clearPage("Updated privacy statement");
    var statement = el("div", "I acknowledge the updated privacy conditions for my healthcare account. Acceptance permits hospital authorities to proceed with the appointment request described by the patient.", "notice");
    var form = document.createElement("form");
    var checkLabel = el("label", "I have read and accept the updated privacy statement.");
    var check = document.createElement("input");
    check.type = "checkbox";
    check.required = true;
    check.style.width = "auto";
    check.style.marginRight = ".5rem";
    checkLabel.prepend(check);
    var feedback = message("", "error");
    feedback.classList.add("hidden");
    form.append(checkLabel, button("Accept privacy statement"), feedback);
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      var result = await api("/api/privacy/accept", { accepted: check.checked });
      feedback.textContent = result.data.message || "Privacy acceptance could not be saved.";
      feedback.className = result.ok ? "success" : "error";
      feedback.classList.remove("hidden");
      if (result.ok) {
        log("Privacy statement acceptance simulated successfully.");
        setTimeout(renderSuccess, 250);
      }
    });
    content.append(statement, form);
  }

  function renderSuccess() {
    clearPage("Recovery complete");
    content.append(
      el("p", "Your password has been reset and the updated privacy statement has been accepted."),
      el("p", "The hospital can now continue the appointment booking process."),
      el("div", "For your safety, do not disclose your new password or any verification code to anyone, including callers claiming to be support staff.", "notice")
    );
  }

  window.addEventListener("hashchange", route);
  fetch("/api/bootstrap", { credentials: "same-origin" })
    .then(function (response) { return response.json(); })
    .then(function (data) {
      csrf = data.csrf || "";
      if (!csrf) throw new Error("No session security token");
      log("Secure session initialized. CSRF protection is active.");
      route();
    })
    .catch(function () {
      clearPage("Service unavailable");
      content.append(message("The secure recovery service is unavailable. Please refresh and try again.", "error"));
    });
}());
</script>
</body>
</html>`;
}

async function handler(request: Request): Promise<Response> {
  cleanOldState();

  const url = new URL(request.url);
  if (url.protocol !== "https:") {
    return new Response("HTTPS is required.", { status: 400, headers: headers() });
  }

  const { session, isNew } = sessionFor(request);
  const cookieHeaders = headers();
  if (isNew) cookieHeaders.append("Set-Cookie", sessionCookie(session));

  if (request.method === "GET" && url.pathname === "/api/bootstrap") {
    return json({ csrf: session.csrf }, 200, cookieHeaders);
  }

  if (request.method === "POST" && url.pathname.startsWith("/api/")) {
    if (!csrfValid(request, session)) {
      return json({ message: "Your secure session could not be verified. Refresh the page and try again." }, 403, cookieHeaders);
    }

    const body = await safeBody(request);
    if (!body) return json({ message: "Please submit a valid request." }, 400, cookieHeaders);

    // [1][4] Generic recovery response and per-session rate limit.
    if (url.pathname === "/api/recovery/request") {
      if (isThrottled(session.recoveryAttempts, RECOVERY_LIMIT)) {
        return json({ message: "For security, please wait before making another recovery request." }, 429, cookieHeaders);
      }
      recordAttempt(session.recoveryAttempts);
      if (!safeEmail(body.email)) {
        return json({ message: "Enter a valid email address to continue." }, 400, cookieHeaders);
      }
      const rawToken = randomToken(32);
      resetTokens.set(sha256(rawToken), {
        sessionId: session.id,
        expiresAt: Date.now() + RESET_TTL_MS,
        used: false,
        verified: false,
        mfaComplete: false,
      });
      return json({
        message: "If the request can be processed, reset instructions have been prepared.",
        testToken: rawToken,
        resetLink: "/?screen=verify&token=" + encodeURIComponent(rawToken),
      }, 200, cookieHeaders);
    }

    // [3][4] Opaque hashed token, session-bound, expiry and guessing protection.
    if (url.pathname === "/api/recovery/verify") {
      if (isThrottled(session.verificationAttempts, VERIFY_LIMIT)) {
        return json({ message: "Too many verification attempts. Please wait and request a new reset link if needed." }, 429, cookieHeaders);
      }
      const record = recordForToken(body.token, session);
      if (!record) {
        recordAttempt(session.verificationAttempts);
        return json({ message: "We could not verify that reset token. Check it or request a new one." }, 400, cookieHeaders);
      }
      record.verified = true;
      return json({ message: "Reset token verified. Complete the additional security check.", mfaTestCode: MFA_TEST_CODE }, 200, cookieHeaders);
    }

    // [4] Deterministic mock MFA only after possession of the bound reset token.
    if (url.pathname === "/api/recovery/mfa") {
      if (isThrottled(session.mfaAttempts, MFA_LIMIT)) {
        return json({ message: "Too many code attempts. Please wait and begin recovery again if necessary." }, 429, cookieHeaders);
      }
      const record = recordForToken(body.token, session);
      if (!record || !record.verified) {
        return json({ message: "We could not confirm this security check. Start recovery again." }, 400, cookieHeaders);
      }
      if (typeof body.code !== "string" || body.code !== MFA_TEST_CODE) {
        recordAttempt(session.mfaAttempts);
        return json({ message: "We could not confirm that code. Please try again." }, 400, cookieHeaders);
      }
      record.mfaComplete = true;
      return json({ message: "Identity confirmation complete." }, 200, cookieHeaders);
    }

    // [4] Password never stored plaintext; Bun Argon2id password hashing.
    if (url.pathname === "/api/recovery/reset") {
      const record = recordForToken(body.token, session);
      if (!record || !record.verified || !record.mfaComplete) {
        return json({ message: "This password reset session is not valid. Start recovery again." }, 403, cookieHeaders);
      }
      const policy = strongPassword(body.password);
      if (!policy.valid) return json({ message: policy.message }, 400, cookieHeaders);
      try {
        await Bun.password.hash(body.password as string, { algorithm: "argon2id" });
      } catch {
        return json({ message: "Password update is temporarily unavailable. Please try again." }, 503, cookieHeaders);
      }
      record.used = true;
      session.authenticated = true;
      return json({ message: "Your password has been securely updated." }, 200, cookieHeaders);
    }

    // [1] Authenticated, session-owned, CSRF-protected privacy acceptance.
    if (url.pathname === "/api/privacy/accept") {
      if (!session.authenticated) {
        return json({ message: "Please complete secure account recovery before accepting this statement." }, 403, cookieHeaders);
      }
      if (body.accepted !== true) {
        return json({ message: "Please confirm acceptance to continue." }, 400, cookieHeaders);
      }
      session.privacyAccepted = true;
      return json({ message: "Updated privacy statement accepted." }, 200, cookieHeaders);
    }

    return json({ message: "This service endpoint is unavailable." }, 404, cookieHeaders);
  }

  if (request.method !== "GET") {
    return new Response("Method not allowed.", { status: 405, headers: cookieHeaders });
  }

  const nonce = randomToken(18);
  const pageHeaders = headers(nonce);
  if (isNew) pageHeaders.append("Set-Cookie", sessionCookie(session));
  pageHeaders.set("Content-Type", "text/html; charset=utf-8");
  return new Response(appHtml(nonce), { status: 200, headers: pageHeaders });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
});

console.log("Hospital recovery server listening securely on https://localhost:3000");
