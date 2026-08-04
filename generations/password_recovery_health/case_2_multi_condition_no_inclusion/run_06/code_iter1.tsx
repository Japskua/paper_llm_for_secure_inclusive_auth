
import { existsSync } from "node:fs";

/*
  Password Recovery System
  Single Bun HTTPS server and inline SPA.
  Security controls are mapped to requirements sections 1–5 below.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(Bun.env.PORT || 3000);

type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  recoveryId?: string;
  recoveryRequests: number[];
};

type Recovery = {
  id: string;
  sessionId: string;
  tokenHash: string;
  tokenExpiresAt: number;
  tokenUsed: boolean;
  tokenAttempts: number;
  tokenBlockedUntil: number;
  mfaVerified: boolean;
  mfaAttempts: number;
  mfaBlockedUntil: number;
  passwordAttempts: number;
  passwordBlockedUntil: number;
  passwordHash?: string;
  privacyAccepted: boolean;
};

const sessions = new Map<string, Session>();
const recoveries = new Map<string, Recovery>();

const SESSION_TTL = 30 * 60 * 1000;
const RESET_TTL = 15 * 60 * 1000;
const ATTEMPT_LIMIT = 5;
const BLOCK_MS = 60 * 1000;
const MFA_CODE = "246810";

/* Requirement 3: cryptographically secure, unpredictable opaque values. */
function randomHex(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

function parseCookies(request: Request): Record<string, string> {
  const header = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of header.split(";")) {
    const separator = item.indexOf("=");
    if (separator > 0) {
      const key = item.slice(0, separator).trim();
      const value = item.slice(separator + 1).trim();
      if (/^[A-Za-z0-9_-]+$/.test(value)) result[key] = value;
    }
  }
  return result;
}

function getSession(request: Request): Session | undefined {
  const sid = parseCookies(request).sid;
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return undefined;
  const session = sessions.get(sid);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sid);
    return undefined;
  }
  return session;
}

function createSession(): Session {
  const session: Session = {
    id: randomHex(),
    csrf: randomHex(),
    expiresAt: Date.now() + SESSION_TTL,
    recoveryRequests: [],
  };
  sessions.set(session.id, session);
  return session;
}

/* Requirements 1 and 3: secure, HttpOnly session cookie and common hardening headers. */
function securityHeaders(nonce: string): Headers {
  const headers = new Headers();
  headers.set("Content-Security-Policy",
    "default-src 'self'; script-src 'nonce-" + nonce +
    "'; style-src 'nonce-" + nonce +
    "'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function json(data: unknown, status = 200, extra?: Headers): Response {
  const nonce = randomHex(16);
  const headers = extra || securityHeaders(nonce);
  if (!headers.has("Content-Security-Policy")) {
    for (const [key, value] of securityHeaders(nonce)) headers.set(key, value);
  }
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400): Response {
  return json({ ok: false, message: "We could not complete that request. Please try again." }, status);
}

/* Requirement 1: all state-changing requests require both same-session CSRF values. */
function validCsrf(request: Request, body: Record<string, unknown>, session: Session): boolean {
  const header = request.headers.get("x-csrf-token") || "";
  const bodyToken = typeof body.csrf === "string" ? body.csrf : "";
  return header.length === 64 && header === session.csrf && bodyToken === session.csrf;
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function ownedRecovery(session: Session): Recovery | undefined {
  if (!session.recoveryId) return undefined;
  const recovery = recoveries.get(session.recoveryId);
  if (!recovery || recovery.sessionId !== session.id) return undefined;
  return recovery;
}

function isBlocked(until: number): boolean {
  return until > Date.now();
}

function registerFailure(recovery: Recovery, field: "token" | "mfa" | "password"): void {
  const attemptsKey = (field + "Attempts") as "tokenAttempts" | "mfaAttempts" | "passwordAttempts";
  const blockedKey = (field + "BlockedUntil") as "tokenBlockedUntil" | "mfaBlockedUntil" | "passwordBlockedUntil";
  recovery[attemptsKey] += 1;
  if (recovery[attemptsKey] >= ATTEMPT_LIMIT) {
    recovery[blockedKey] = Date.now() + BLOCK_MS;
    recovery[attemptsKey] = 0;
  }
}

/* Requirement 4: strong local password policy, without returning password details. */
function strongPassword(password: string): boolean {
  return password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password);
}

const approvedPages = new Set(["/", "/recover", "/verify", "/mfa", "/reset", "/privacy", "/confirmation"]);

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --navy:#12304a; --blue:#1769aa; --pale:#edf6fb; --line:#bfd0dc; --ink:#16232d; --good:#176844; --warn:#754b00; --danger:#a52828; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f5f8fa; color:var(--ink); font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
    header { background:var(--navy); color:white; padding:1.2rem 1rem; border-bottom:4px solid #62b5d8; }
    header div, main, footer { max-width:760px; margin:auto; }
    h1 { font-size:1.45rem; margin:0; }
    header p { margin:.2rem 0 0; font-size:.93rem; }
    main { padding:1.5rem 1rem 2rem; }
    .card { background:white; border:1px solid var(--line); border-radius:8px; box-shadow:0 1px 3px #12304a18; padding:1.3rem; }
    h2 { margin-top:0; color:var(--navy); font-size:1.35rem; }
    h3 { color:var(--navy); font-size:1.05rem; }
    label { display:block; font-weight:bold; margin:1rem 0 .3rem; }
    input { width:100%; padding:.7rem; border:1px solid #778b98; border-radius:4px; font:inherit; }
    input:focus { outline:3px solid #8cc9e4; outline-offset:1px; }
    button, .button-link { display:inline-block; margin-top:1rem; padding:.7rem 1rem; border:0; border-radius:4px; background:var(--blue); color:white; font-weight:bold; font:inherit; text-decoration:none; cursor:pointer; }
    button:hover, .button-link:hover { background:#0d538b; }
    .secondary { background:#e7eff4; color:#173447; }
    .notice { margin:1rem 0; padding:.8rem; border-left:4px solid var(--blue); background:var(--pale); }
    .warning { border-left-color:var(--warn); background:#fff7e7; }
    .success { border-left-color:var(--good); background:#eaf7ef; }
    .error { border-left-color:var(--danger); background:#fff0f0; }
    .muted { color:#53636e; font-size:.92rem; }
    code { display:inline-block; overflow-wrap:anywhere; padding:.15rem .3rem; background:#eef2f4; border-radius:3px; }
    .checks { padding-left:1.2rem; }
    .checks li { margin:.35rem 0; }
    .row { display:flex; gap:.7rem; flex-wrap:wrap; align-items:center; }
    .checkbox { display:flex; gap:.55rem; align-items:flex-start; font-weight:normal; }
    .checkbox input { width:auto; margin-top:.25rem; }
    footer { padding:0 1rem 2rem; }
    #logs { min-height:4rem; max-height:12rem; overflow:auto; background:#101d26; color:#d7effa; padding:.8rem; border-radius:6px; font:12px/1.45 monospace; white-space:pre-wrap; }
    .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Hospital account recovery</h1>
      <p>Secure access to accept the updated privacy statement</p>
    </div>
  </header>
  <main>
    <div id="view" aria-live="polite"><p>Loading secure recovery…</p></div>
  </main>
  <footer>
    <h2>Recovery activity logs</h2>
    <p class="muted">This training demonstration mirrors simulated delivery messages here and in the browser console.</p>
    <div id="logs" role="log" aria-live="polite">Ready.</div>
  </footer>
  <script nonce="${nonce}">
  (() => {
    "use strict";

    const view = document.getElementById("view");
    const logs = document.getElementById("logs");
    const state = { csrf: "", mockToken: "", mfaCode: "246810", ready: false };

    /* Requirements 2 and 5: all dynamic values use textContent, never HTML injection. */
    function log(message) {
      console.log("[Recovery demo] " + message);
      const line = document.createElement("div");
      line.textContent = new Date().toLocaleTimeString() + " — " + message;
      logs.appendChild(line);
      logs.scrollTop = logs.scrollHeight;
    }

    function element(tag, text, className) {
      const item = document.createElement(tag);
      if (text !== undefined) item.textContent = text;
      if (className) item.className = className;
      return item;
    }

    function notice(text, type) {
      return element("div", text, "notice " + (type || ""));
    }

    function button(text, type) {
      const item = element("button", text);
      item.type = type || "submit";
      return item;
    }

    function link(text, hash, className) {
      const item = element("a", text, className || "button-link");
      item.href = hash;
      return item;
    }

    function clear() {
      view.replaceChildren();
      window.scrollTo(0, 0);
    }

    async function api(path, data) {
      const payload = Object.assign({}, data, { csrf: state.csrf });
      try {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
          body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || "We could not complete that request.");
        return result;
      } catch (error) {
        return { ok: false, message: error instanceof Error ? error.message : "Connection unavailable." };
      }
    }

    function safeHashView() {
      const raw = location.hash.slice(1) || "recover";
      const name = raw.split("?")[0];
      return ["recover", "verify", "mfa", "reset", "privacy", "confirmation"].includes(name) ? name : "recover";
    }

    function hashToken() {
      const raw = location.hash.slice(1);
      const query = raw.includes("?") ? raw.slice(raw.indexOf("?") + 1) : "";
      const token = new URLSearchParams(query).get("token") || "";
      return /^[a-f0-9]{64}$/.test(token) ? token : "";
    }

    function safeGuidance() {
      const section = element("section");
      section.append(
        element("h3", "Keep your account safe"),
        element("p", "Use this hospital address directly. Hospital staff will never ask you to share a password, recovery token, or MFA code by email, text message, or phone."),
        element("p", "Do not follow unfamiliar links or enter account details into pages reached from unexpected messages.", "muted")
      );
      return section;
    }

    function recoveryView() {
      clear();
      const card = element("section", undefined, "card");
      const form = document.createElement("form");
      form.noValidate = true;
      const email = document.createElement("input");
      email.id = "recovery-email";
      email.name = "email";
      email.type = "email";
      email.autocomplete = "email";
      email.maxLength = 254;
      email.required = true;
      const label = element("label", "Email address used for your hospital account");
      label.htmlFor = email.id;
      form.append(label, email, element("p", "For privacy, the same response is shown whether or not an account is available.", "muted"), button("Send recovery instructions"));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const result = await api("/api/recovery", { email: email.value });
        if (!result.ok) {
          form.prepend(notice(result.message, "error"));
          return;
        }
        state.mockToken = typeof result.mockToken === "string" ? result.mockToken : "";
        log("Simulated recovery delivery created in this browser. Test reset token: " + state.mockToken);
        form.replaceWith(recoveryDelivery(state.mockToken));
      });
      card.append(element("h2", "Recover your account"), notice("Enter your email address to begin. We do not confirm whether an account exists.", "warning"), form, safeGuidance());
      view.append(card);
    }

    function recoveryDelivery(token) {
      const area = element("section");
      const tokenCode = element("code", token);
      const go = link("Continue to token verification", "#verify?token=" + encodeURIComponent(token));
      area.append(
        notice("If an eligible account is available, recovery instructions have been prepared. In this demo, the test token is shown below and logged in the browser console.", "success"),
        element("p", "Test-only recovery token:"),
        tokenCode,
        element("div", undefined, "row")
      );
      area.lastChild.append(go, link("Start over", "#recover", "button-link secondary"));
      return area;
    }

    function verifyView() {
      clear();
      const card = element("section", undefined, "card");
      const form = document.createElement("form");
      const token = document.createElement("input");
      token.id = "reset-token";
      token.type = "text";
      token.inputMode = "text";
      token.autocomplete = "one-time-code";
      token.maxLength = 64;
      token.value = hashToken() || state.mockToken;
      const label = element("label", "Recovery token");
      label.htmlFor = token.id;
      form.append(label, token, element("p", "A token from the recovery link can be submitted manually here.", "muted"), button("Verify recovery token"));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const result = await api("/api/verify-token", { token: token.value.trim() });
        if (!result.ok) {
          form.prepend(notice(result.message, "error"));
          return;
        }
        log("Recovery token verified for this recovery session.");
        location.hash = "#mfa";
      });
      card.append(element("h2", "Verify recovery token"), notice("For your protection, recovery tokens expire quickly and can be used once.", "warning"), form, safeGuidance());
      view.append(card);
    }

    function mfaView() {
      clear();
      const card = element("section", undefined, "card");
      const form = document.createElement("form");
      const code = document.createElement("input");
      code.id = "mfa-code";
      code.type = "text";
      code.inputMode = "numeric";
      code.autocomplete = "one-time-code";
      code.maxLength = 6;
      const label = element("label", "Six-digit verification code");
      label.htmlFor = code.id;
      form.append(label, code, button("Verify code"));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const result = await api("/api/verify-mfa", { code: code.value.trim() });
        if (!result.ok) {
          form.prepend(notice(result.message, "error"));
          return;
        }
        log("Simulated MFA verification completed for this recovery session.");
        location.hash = "#reset";
      });
      log("Simulated MFA delivery in this browser. Deterministic test code: " + state.mfaCode);
      card.append(
        element("h2", "Additional verification"),
        notice("Demo delivery: use the displayed test code " + state.mfaCode + ". It is also logged in the browser console.", "success"),
        form,
        safeGuidance()
      );
      view.append(card);
    }

    function resetView() {
      clear();
      const card = element("section", undefined, "card");
      const form = document.createElement("form");
      const password = document.createElement("input");
      password.id = "new-password";
      password.type = "password";
      password.name = "new-password";
      password.autocomplete = "new-password";
      password.maxLength = 128;
      const confirm = document.createElement("input");
      confirm.id = "confirm-password";
      confirm.type = "password";
      confirm.autocomplete = "new-password";
      confirm.maxLength = 128;
      const passwordLabel = element("label", "New password");
      passwordLabel.htmlFor = password.id;
      const confirmLabel = element("label", "Confirm new password");
      confirmLabel.htmlFor = confirm.id;
      form.append(
        passwordLabel, password,
        confirmLabel, confirm,
        element("ul", undefined, "checks")
      );
      const list = form.lastChild;
      ["At least 12 characters", "Uppercase and lowercase letters", "A number and a symbol"].forEach((item) => list.append(element("li", item)));
      form.append(button("Save new password"));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (password.value !== confirm.value) {
          form.prepend(notice("The passwords do not match.", "error"));
          password.value = "";
          confirm.value = "";
          return;
        }
        const submitted = password.value;
        password.value = "";
        confirm.value = "";
        const result = await api("/api/reset-password", { password: submitted });
        if (!result.ok) {
          form.prepend(notice(result.message, "error"));
          return;
        }
        log("Password reset completed. Submitted password was not logged or retained in the interface.");
        location.hash = "#privacy";
      });
      card.append(element("h2", "Create a new password"), notice("Choose a new password that is not shared with anyone else.", "warning"), form, safeGuidance());
      view.append(card);
    }

    function privacyView() {
      clear();
      const card = element("section", undefined, "card");
      const form = document.createElement("form");
      const check = document.createElement("input");
      check.type = "checkbox";
      check.id = "privacy-check";
      const checkLabel = element("label", undefined, "checkbox");
      checkLabel.htmlFor = check.id;
      checkLabel.append(check, document.createTextNode(" I have read and accept the updated privacy statement for my healthcare account."));
      form.append(
        element("p", "The updated statement explains how hospital authorities may process information required to arrange care. This demo intentionally does not display patient records or personal data."),
        checkLabel,
        button("Accept privacy statement")
      );
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!check.checked) {
          form.prepend(notice("Please select the acknowledgement before continuing.", "error"));
          return;
        }
        const result = await api("/api/accept-privacy", { accepted: true });
        if (!result.ok) {
          form.prepend(notice(result.message, "error"));
          return;
        }
        log("Privacy statement acceptance recorded for the current recovery session.");
        location.hash = "#confirmation";
      });
      card.append(element("h2", "Updated privacy statement"), form, safeGuidance());
      view.append(card);
    }

    function confirmationView() {
      clear();
      const card = element("section", undefined, "card");
      card.append(
        element("h2", "Recovery complete"),
        notice("Your password has been updated and the privacy statement acknowledgement has been recorded.", "success"),
        element("p", "You may now return to the hospital account sign-in page through your normal trusted hospital bookmark."),
        link("Begin another recovery", "#recover", "button-link secondary"),
        safeGuidance()
      );
      view.append(card);
    }

    function render() {
      if (!state.ready) return;
      const target = safeHashView();
      if (target === "recover") recoveryView();
      else if (target === "verify") verifyView();
      else if (target === "mfa") mfaView();
      else if (target === "reset") resetView();
      else if (target === "privacy") privacyView();
      else confirmationView();
    }

    window.addEventListener("hashchange", render);

    fetch("/api/bootstrap", { credentials: "same-origin" })
      .then((response) => response.json())
      .then((data) => {
        if (!data || typeof data.csrf !== "string") throw new Error("Unable to initialize secure session.");
        state.csrf = data.csrf;
        state.ready = true;
        log("Secure recovery session initialized.");
        if (!location.hash) location.hash = "#recover";
        else render();
      })
      .catch(() => {
        clear();
        view.append(notice("A secure session could not be started. Please reload this trusted hospital page.", "error"));
      });
  })();
  </script>
</body>
</html>`;
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    /* Requirement 3: HTTPS listener only; no HTTP application route is served. */
    if (request.method === "GET" && approvedPages.has(url.pathname)) {
      const nonce = randomHex(16);
      const headers = securityHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { status: 200, headers });
    }

    if (request.method === "GET" && url.pathname === "/api/bootstrap") {
      let session = getSession(request);
      const headers = securityHeaders(randomHex(16));
      if (!session) {
        session = createSession();
        headers.append("Set-Cookie",
          "sid=" + session.id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(SESSION_TTL / 1000));
      }
      return json({ ok: true, csrf: session.csrf }, 200, headers);
    }

    if (request.method !== "POST" || !url.pathname.startsWith("/api/")) {
      return new Response("Not found", { status: 404, headers: securityHeaders(randomHex(16)) });
    }

    const body = await readBody(request);
    const session = getSession(request);
    if (!body || !session || !validCsrf(request, body, session)) return genericError(403);

    if (url.pathname === "/api/recovery") {
      /* Requirements 1, 3, 4: no account lookup disclosure; opaque session-owned record only. */
      const now = Date.now();
      session.recoveryRequests = session.recoveryRequests.filter((time) => time > now - 60_000);
      if (session.recoveryRequests.length >= 3) {
        return json({ ok: false, message: "Please wait before requesting another recovery message." }, 429);
      }
      session.recoveryRequests.push(now);

      const suppliedEmail = typeof body.email === "string" ? body.email.trim() : "";
      const validEmail = suppliedEmail.length <= 254 && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(suppliedEmail);
      const token = randomHex();
      const recovery: Recovery = {
        id: randomHex(),
        sessionId: session.id,
        tokenHash: await sha256(token),
        tokenExpiresAt: now + RESET_TTL,
        tokenUsed: false,
        tokenAttempts: 0,
        tokenBlockedUntil: 0,
        mfaVerified: false,
        mfaAttempts: 0,
        mfaBlockedUntil: 0,
        passwordAttempts: 0,
        passwordBlockedUntil: 0,
        privacyAccepted: false,
      };
      session.recoveryId = recovery.id;
      recoveries.set(recovery.id, recovery);

      /* Deliberately generic response regardless of supplied address validity/account availability. */
      return json({
        ok: true,
        message: "If an eligible account is available, recovery instructions have been prepared.",
        mockToken: token,
        acceptedFormat: validEmail,
      });
    }

    const recovery = ownedRecovery(session);
    if (!recovery) return genericError(403);

    if (url.pathname === "/api/verify-token") {
      if (isBlocked(recovery.tokenBlockedUntil)) {
        return json({ ok: false, message: "Too many attempts. Please wait one minute before trying again." }, 429);
      }
      const token = typeof body.token === "string" ? body.token.trim() : "";
      const validFormat = /^[a-f0-9]{64}$/.test(token);
      const valid = validFormat &&
        !recovery.tokenUsed &&
        recovery.tokenExpiresAt > Date.now() &&
        (await sha256(token)) === recovery.tokenHash;
      if (!valid) {
        registerFailure(recovery, "token");
        return json({ ok: false, message: "The recovery token could not be verified. Check it and try again." }, 400);
      }
      recovery.tokenUsed = true;
      recovery.tokenHash = "";
      return json({ ok: true });
    }

    if (url.pathname === "/api/verify-mfa") {
      if (!recovery.tokenUsed) return genericError(403);
      if (isBlocked(recovery.mfaBlockedUntil)) {
        return json({ ok: false, message: "Too many attempts. Please wait one minute before trying again." }, 429);
      }
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (code !== MFA_CODE) {
        registerFailure(recovery, "mfa");
        return json({ ok: false, message: "The verification code could not be verified. Try again." }, 400);
      }
      recovery.mfaVerified = true;
      return json({ ok: true });
    }

    if (url.pathname === "/api/reset-password") {
      if (!recovery.tokenUsed || !recovery.mfaVerified) return genericError(403);
      if (isBlocked(recovery.passwordBlockedUntil)) {
        return json({ ok: false, message: "Too many attempts. Please wait one minute before trying again." }, 429);
      }
      let password = typeof body.password === "string" ? body.password : "";
      if (!strongPassword(password)) {
        registerFailure(recovery, "password");
        password = "";
        return json({ ok: false, message: "Use a password with at least 12 characters, upper and lowercase letters, a number, and a symbol." }, 400);
      }

      /* Requirement 4: bcrypt only; plaintext is not stored, rendered, or logged. */
      recovery.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 12 });
      password = "";
      return json({ ok: true });
    }

    if (url.pathname === "/api/accept-privacy") {
      if (!recovery.passwordHash || !recovery.tokenUsed || !recovery.mfaVerified) return genericError(403);
      if (body.accepted !== true) return genericError(400);
      recovery.privacyAccepted = true;
      return json({ ok: true });
    }

    return new Response("Not found", { status: 404, headers: securityHeaders(randomHex(16)) });
  } catch {
    /* Requirement 3: generic production errors without stack traces or debug details. */
    return genericError(500);
  }
}

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  throw new Error("TLS certificate files are required.");
}

/* Requirement 3: Bun HTTPS server uses the provided localhost mkcert files. */
Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file(CERT_PATH),
    key: Bun.file(KEY_PATH),
  },
  fetch: handler,
});
