
import { existsSync } from "node:fs";

/*
  Password Recovery System
  Single-file Bun HTTPS server and browser SPA.
  Run with: bun app.ts
*/

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3001);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

type ResetRecord = {
  token: string;
  expiresAt: number;
  verified: boolean;
  attempts: number;
  requestCount: number;
  requestWindow: number;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  mfaPending: boolean;
  mfaCode?: string;
  mfaExpiresAt?: number;
  mfaFailures: number;
  mfaLockedUntil: number;
  loginFailures: number;
  loginWindow: number;
  lockedUntil: number;
  reset?: ResetRecord;
};

const sessions = new Map<string, Session>();
const SESSION_COOKIE = "__Host-recovery_sid";
const TOKEN_LIFETIME_MS = 10 * 60 * 1000;
const MFA_LIFETIME_MS = 10 * 60 * 1000;
const MFA_LOCKOUT_MS = 15 * 60 * 1000;
const MFA_VERIFY_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const RESET_WINDOW_MS = 15 * 60 * 1000;
const RESET_LIMIT = 3;
const VERIFY_LIMIT = 5;

/* Authentication safeguard: password is only held as an Argon2id hash in memory. */
let storedPasswordHash = await Bun.password.hash("HospitalDemo!2026", {
  algorithm: "argon2id",
});

function randomHex(bytes = 32): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Buffer.from(data).toString("hex");
}

/* Requirement: cryptographically random, six-digit, session-only MFA code. */
function randomMfaCode(): string {
  const values = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / 1_000_000) * 1_000_000;
  do {
    crypto.getRandomValues(values);
  } while (values[0] >= limit);
  return String(values[0] % 1_000_000).padStart(6, "0");
}

function newSession(): Session {
  return {
    id: randomHex(32),
    csrf: randomHex(32),
    createdAt: Date.now(),
    authenticated: false,
    privacyAccepted: false,
    mfaPending: false,
    mfaFailures: 0,
    mfaLockedUntil: 0,
    loginFailures: 0,
    loginWindow: Date.now(),
    lockedUntil: 0,
  };
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const header = request.headers.get("cookie") || "";
  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index > 0) {
      const key = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      if (/^[A-Za-z0-9_-]+$/.test(key) && /^[A-Za-z0-9_-]+$/.test(value)) {
        result[key] = value;
      }
    }
  }
  return result;
}

function getSession(request: Request, create = false): { session?: Session; isNew: boolean } {
  const sid = parseCookies(request)[SESSION_COOKIE];
  if (sid && sessions.has(sid)) return { session: sessions.get(sid), isNew: false };
  if (!create) return { isNew: false };
  const session = newSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function cleanupSessions() {
  const oldest = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, session] of sessions) {
    if (session.createdAt < oldest) sessions.delete(id);
  }
}

function secureHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      `script-src 'nonce-${nonce || "none"}'`,
      `style-src 'nonce-${nonce || "none"}'`,
      "connect-src 'self'",
      "img-src 'self' data:",
      "font-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join("; "),
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400`;
}

function json(data: unknown, status = 200, session?: Session): Response {
  const headers = secureHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (session) headers.append("Set-Cookie", sessionCookie(session));
  return new Response(JSON.stringify(data), { status, headers });
}

function safeError(message = "We could not complete that step. Please try again."): Response {
  return json({ ok: false, message }, 400);
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 12_000) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function stringField(body: Record<string, unknown>, field: string, max = 300): string | null {
  const value = body[field];
  if (typeof value !== "string" || value.length > max) return null;
  return value;
}

/* CSRF/access-control safeguard: every state-changing and recovery-state request checks this token. */
function csrfValid(session: Session | undefined, body: Record<string, unknown> | null): boolean {
  if (!session || !body) return false;
  const csrf = body.csrf;
  return typeof csrf === "string" && csrf.length === session.csrf.length &&
    crypto.timingSafeEqual(new TextEncoder().encode(csrf), new TextEncoder().encode(session.csrf));
}

function validEmailShape(value: string): boolean {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validToken(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function validMfaCode(value: string): boolean {
  return /^[0-9]{6}$/.test(value);
}

function passwordProblem(password: string): string | null {
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) ||
    !/[^A-Za-z0-9\s]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  if (/\s/.test(password)) return "Do not use spaces.";
  if (/^(password|hospital|welcome|123456)/i.test(password)) return "Choose a less predictable password.";
  return null;
}

function resetValid(session: Session, token: string, requireVerified = false): boolean {
  const reset = session.reset;
  if (!reset || !validToken(token) || reset.expiresAt < Date.now()) return false;
  if (requireVerified && !reset.verified) return false;
  return crypto.timingSafeEqual(new TextEncoder().encode(reset.token), new TextEncoder().encode(token));
}

function codeMatches(expected: string, actual: string): boolean {
  if (!validMfaCode(actual) || expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(new TextEncoder().encode(expected), new TextEncoder().encode(actual));
}

/* XSS safeguard: no request value is interpolated into HTML; only static server messages are returned. */
async function handleApi(request: Request, pathname: string): Promise<Response> {
  cleanupSessions();
  const { session } = getSession(request, false);
  const body = await readBody(request);

  if (!session || !csrfValid(session, body)) {
    return safeError("Your secure form has expired. Refresh the page and try again.");
  }

  /*
    Recovery pause/resume safeguard: server, rather than local browser storage, decides
    whether a reset token is still usable and whether it was confirmed.
  */
  if (pathname === "/api/recovery/state") {
    const reset = session.reset;
    if (!reset || reset.expiresAt < Date.now()) {
      session.reset = undefined;
      return json({ ok: true, recoveryStage: "start" });
    }
    return json({
      ok: true,
      recoveryStage: reset.verified ? "password" : "code",
      token: reset.token,
      expiresInMinutes: Math.max(1, Math.ceil((reset.expiresAt - Date.now()) / 60000)),
    });
  }

  if (pathname === "/api/reset/request") {
    const contact = stringField(body, "contact");
    if (!contact || !validEmailShape(contact)) {
      return json({ ok: true, message: "If the details match an account, a recovery code has been prepared." });
    }

    const now = Date.now();
    const previous = session.reset;
    const inWindow = previous && now - previous.requestWindow < RESET_WINDOW_MS;
    const count = inWindow ? previous.requestCount : 0;
    if (count >= RESET_LIMIT) {
      return json({ ok: true, message: "If the details match an account, a recovery code has been prepared." });
    }

    const token = randomHex(32);
    session.reset = {
      token,
      expiresAt: now + TOKEN_LIFETIME_MS,
      verified: false,
      attempts: 0,
      requestCount: count + 1,
      requestWindow: inWindow ? previous!.requestWindow : now,
    };

    console.log("[mock delivery] Password recovery code prepared for this browser session.");
    return json({
      ok: true,
      message: "If the details match an account, a recovery code has been prepared.",
      mockToken: token,
      expiresInMinutes: 10,
    });
  }

  if (pathname === "/api/reset/verify") {
    const token = stringField(body, "token", 80);
    if (!token || !validToken(token) || !session.reset) {
      return safeError("That recovery code is not available. Request a new code and try again.");
    }
    if (session.reset.attempts >= VERIFY_LIMIT) {
      return safeError("Too many code attempts were made. Request a new code when you are ready.");
    }
    if (!resetValid(session, token)) {
      session.reset.attempts++;
      return safeError("That recovery code is not available. Request a new code and try again.");
    }
    session.reset.verified = true;
    return json({ ok: true, message: "Code confirmed. You can now choose a new password." });
  }

  if (pathname === "/api/reset/password") {
    const token = stringField(body, "token", 80);
    const password = stringField(body, "password", 130);
    if (!token || !password || !resetValid(session, token, true)) {
      return safeError("Your confirmed recovery step is no longer available. Start again when ready.");
    }
    const problem = passwordProblem(password);
    if (problem) return json({ ok: false, message: problem }, 400);

    storedPasswordHash = await Bun.password.hash(password, { algorithm: "argon2id" });
    session.reset = undefined;
    console.log("[mock verification] Password replacement completed securely.");
    return json({ ok: true, message: "Your password has been changed. Sign in when you are ready." });
  }

  if (pathname === "/api/signin") {
    const identifier = stringField(body, "identifier");
    const password = stringField(body, "password", 130);
    const now = Date.now();

    if (session.lockedUntil > now) {
      return safeError("Sign-in is temporarily paused for safety. Please return later.");
    }
    if (now - session.loginWindow > LOGIN_WINDOW_MS) {
      session.loginWindow = now;
      session.loginFailures = 0;
    }

    const allowedIdentifier = !!identifier && validEmailShape(identifier);
    const passwordMatches = !!password && await Bun.password.verify(password, storedPasswordHash);
    if (!allowedIdentifier || !passwordMatches) {
      session.loginFailures++;
      if (session.loginFailures >= 5) session.lockedUntil = now + LOCKOUT_MS;
      return safeError("We could not sign you in with those details.");
    }

    session.loginFailures = 0;
    session.authenticated = false;
    session.privacyAccepted = false;
    session.mfaPending = true;
    session.mfaFailures = 0;
    session.mfaLockedUntil = 0;
    session.mfaCode = randomMfaCode();
    session.mfaExpiresAt = now + MFA_LIFETIME_MS;
    console.log("[mock MFA] A cryptographically random sign-in code was prepared for this browser session.");
    /* The simulated browser-delivery response is the sole response that reveals this code. */
    return json({
      ok: true,
      message: "A verification code is ready for this sign-in step.",
      mockMfaCode: session.mfaCode,
      expiresInMinutes: 10,
    });
  }

  if (pathname === "/api/mfa") {
    const now = Date.now();
    const code = stringField(body, "code", 12);

    if (session.mfaLockedUntil > now) {
      return safeError("This verification step is temporarily paused for safety. Restart sign-in later.");
    }
    if (!session.mfaPending || !session.mfaCode || !session.mfaExpiresAt || session.mfaExpiresAt < now) {
      session.mfaPending = false;
      session.mfaCode = undefined;
      return safeError("That verification step has expired. Restart sign-in when you are ready.");
    }

    if (!code || !codeMatches(session.mfaCode, code)) {
      session.mfaFailures++;
      if (session.mfaFailures >= MFA_VERIFY_LIMIT) {
        session.mfaPending = false;
        session.mfaCode = undefined;
        session.mfaExpiresAt = undefined;
        session.mfaLockedUntil = now + MFA_LOCKOUT_MS;
        return safeError("Too many verification attempts were made. For safety, restart sign-in after the pause.");
      }
      return safeError(`That verification code could not be confirmed. You have ${MFA_VERIFY_LIMIT - session.mfaFailures} attempt(s) remaining.`);
    }

    session.mfaPending = false;
    session.mfaCode = undefined;
    session.mfaExpiresAt = undefined;
    session.mfaFailures = 0;
    session.authenticated = true;
    return json({ ok: true, message: "Sign-in confirmed." });
  }

  /* Protected account routes: no identifiers, patient data, or IDOR-style object parameters exist. */
  if (pathname === "/api/privacy") {
    if (!session.authenticated) return json({ ok: false, message: "Please sign in to continue." }, 401);
    session.privacyAccepted = true;
    console.log("[mock privacy] Updated privacy statement accepted in this session.");
    return json({ ok: true, message: "The updated privacy statement has been accepted." });
  }

  if (pathname === "/api/appointment") {
    if (!session.authenticated) return json({ ok: false, message: "Please sign in to continue." }, 401);
    if (!session.privacyAccepted) {
      return json({ ok: false, message: "Please accept the updated privacy statement before requesting an appointment." }, 403);
    }
    console.log("[mock appointment] Medication review appointment request confirmed.");
    return json({ ok: true, message: "Your medication review appointment request is confirmed." });
  }

  return json({ ok: false, message: "That request is not available." }, 404);
}

function page(nonce: string, csrf: string, initialStage: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme:light; --ink:#17324d; --blue:#075b9d; --pale:#edf6fb; --line:#c9d8e4; --ok:#176b46; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f6f8fa; color:#172431; font:18px/1.55 Arial,sans-serif; }
    header { background:#fff; border-bottom:4px solid var(--blue); padding:1rem max(1.25rem,calc((100% - 920px)/2)); }
    header strong { color:var(--ink); font-size:1.15rem; }
    main { max-width:920px; margin:0 auto; padding:1.25rem; }
    .layout { display:grid; grid-template-columns:minmax(0,1fr) 250px; gap:1.25rem; }
    .card,aside { background:#fff; border:1px solid var(--line); border-radius:10px; padding:1.35rem; }
    .logs-card { margin-top:1.25rem; }
    h1 { color:var(--ink); font-size:1.7rem; line-height:1.25; margin:.1rem 0 .75rem; }
    h2 { font-size:1.15rem; color:var(--ink); margin:1rem 0 .4rem; }
    p { margin:.55rem 0; }
    label { display:block; font-weight:bold; margin-top:1rem; }
    input { width:100%; max-width:510px; font:inherit; padding:.65rem; border:2px solid #71869a; border-radius:6px; }
    input:focus,button:focus,a:focus { outline:3px solid #f4b63f; outline-offset:2px; }
    button { display:inline-block; margin:1rem .55rem 0 0; border:0; border-radius:6px; padding:.7rem 1rem; background:var(--blue); color:#fff; font:inherit; font-weight:bold; cursor:pointer; }
    button.secondary { background:#e4edf3; color:#17324d; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    .notice { margin:1rem 0; padding:.8rem; border-left:5px solid var(--blue); background:var(--pale); }
    .success { border-left-color:var(--ok); background:#eff9f3; }
    .error { border-left-color:#9b2525; background:#fff1f1; }
    .progress { padding:0; list-style:none; margin:.5rem 0 1rem; }
    .progress li { padding:.38rem .45rem; border-left:4px solid #bdcbd6; }
    .progress li.current { border-left-color:var(--blue); background:var(--pale); font-weight:bold; }
    .progress li.done { border-left-color:var(--ok); }
    .small,small { font-size:.9rem; }
    details { margin-top:1rem; border-top:1px solid var(--line); padding-top:.7rem; }
    #logs { min-height:5rem; max-height:10rem; overflow:auto; white-space:pre-wrap; background:#102331; color:#e7f4fa; padding:.65rem; font:14px/1.4 monospace; border-radius:5px; }
    footer { max-width:920px; margin:0 auto; padding:0 1.25rem 2rem; font-size:.9rem; }
    @media (max-width:700px) { .layout { grid-template-columns:1fr; } aside { order:-1; } }
  </style>
</head>
<body>
  <header><strong>Hospital account support</strong></header>
  <main>
    <div class="layout">
      <section class="card" aria-labelledby="page-title"><div id="app" aria-live="polite"></div></section>
      <aside aria-label="Your progress and help">
        <h2>Your progress</h2>
        <ol class="progress" id="progress"></ol>
        <p class="small"><strong>No time limit:</strong> You can pause and return to this browser later.</p>
        <button class="secondary" id="pauseButton" type="button">Pause and save place</button>
        <details open>
          <summary><strong>Help and safe sign-in</strong></summary>
          <p class="small">Never share your password or verification code by email, phone, or text. Hospital staff will not ask for it.</p>
          <p class="small">If something feels unexpected, pause here and contact the hospital through its usual published number.</p>
        </details>
      </aside>
    </div>
    <section class="card logs-card" aria-labelledby="log-title">
      <h2 id="log-title">Logs</h2>
      <p class="small">Simulation delivery and verification messages appear here.</p>
      <div id="logs" aria-live="polite">Ready. No private account details are displayed.</div>
    </section>
  </main>
  <footer>Use this secure hospital page only. This recovery simulation does not send email or contact external services.</footer>
  <script nonce="${nonce}">
    (() => {
      "use strict";
      const csrf = ${JSON.stringify(csrf)};
      const initialStage = ${JSON.stringify(initialStage)};
      const app = document.getElementById("app");
      const progress = document.getElementById("progress");
      const logs = document.getElementById("logs");
      const pauseButton = document.getElementById("pauseButton");
      let stage = initialStage;
      let resetToken = "";
      let paused = false;

      function log(message) {
        console.log(message);
        logs.textContent += "\\n" + message;
        logs.scrollTop = logs.scrollHeight;
      }

      function setMessage(text, kind) {
        const box = document.createElement("div");
        box.className = "notice " + (kind || "");
        box.textContent = text;
        app.prepend(box);
      }

      function updateProgress() {
        const items = [
          ["start", "1. Request a code"],
          ["code", "2. Confirm your code"],
          ["password", "3. Choose a password"],
          ["signin", "4. Sign in safely"],
          ["privacy", "5. Accept privacy statement"],
          ["appointment", "6. Confirm appointment"],
        ];
        progress.replaceChildren();
        const index = items.findIndex((item) => item[0] === stage ||
          (stage === "complete" && item[0] === "signin") ||
          (stage === "mfa" && item[0] === "signin"));
        items.forEach((item, i) => {
          const li = document.createElement("li");
          li.textContent = item[1];
          if (i < index) li.className = "done";
          if (i === index) li.className = "current";
          progress.appendChild(li);
        });
      }

      async function post(path, data) {
        try {
          const response = await fetch(path, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(Object.assign({}, data, { csrf }))
          });
          return await response.json();
        } catch (_) {
          return { ok:false, message:"The secure service could not respond. Please try again." };
        }
      }

      function go(path, nextStage) {
        history.pushState({}, "", path);
        stage = nextStage;
        render();
      }

      function button(text, className) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = text;
        if (className) b.className = className;
        return b;
      }

      function render() {
        updateProgress();
        app.replaceChildren();
        const title = document.createElement("h1");
        title.id = "page-title";
        app.appendChild(title);

        if (stage === "start") {
          title.textContent = "Reset your password";
          const intro = document.createElement("p");
          intro.textContent = "We will take this one clear step at a time. Start by entering the email address you use for the hospital account.";
          const label = document.createElement("label");
          label.htmlFor = "contact";
          label.textContent = "Email address";
          const input = document.createElement("input");
          input.id = "contact";
          input.type = "email";
          input.autocomplete = "email";
          const next = button("Prepare recovery code");
          next.addEventListener("click", async () => {
            next.disabled = true;
            const data = await post("/api/reset/request", { contact: input.value.trim() });
            next.disabled = false;
            setMessage(data.message, data.ok ? "success" : "error");
            if (data.ok && data.mockToken) {
              resetToken = data.mockToken;
              log("[mock delivery] Recovery code for browser testing: " + resetToken);
              go("/reset", "code");
              setMessage("Next step: enter the code from the simulated delivery log.", "success");
            }
          });
          const signin = button("I know my password — sign in", "secondary");
          signin.addEventListener("click", () => go("/signin", "signin"));
          app.append(intro, label, input, next, signin);
        } else if (stage === "code") {
          title.textContent = "Confirm your recovery code";
          const p = document.createElement("p");
          p.textContent = "Enter the code from the simulated delivery message. It remains available for 10 minutes and there is no rush.";
          const label = document.createElement("label");
          label.htmlFor = "code";
          label.textContent = "Recovery code";
          const input = document.createElement("input");
          input.id = "code";
          input.autocomplete = "one-time-code";
          input.inputMode = "text";
          input.value = resetToken;
          const verify = button("Confirm code");
          verify.addEventListener("click", async () => {
            const data = await post("/api/reset/verify", { token: input.value.trim().toLowerCase() });
            if (!data.ok) {
              setMessage(data.message, "error");
              return;
            }
            resetToken = input.value.trim().toLowerCase();
            stage = "password";
            render();
            setMessage("Code confirmed. Next step: choose a new password.", "success");
          });
          const back = button("Start again", "secondary");
          back.addEventListener("click", () => {
            resetToken = "";
            go("/", "start");
          });
          app.append(p, label, input, verify, back);
        } else if (stage === "password") {
          title.textContent = "Choose a new password";
          const p = document.createElement("p");
          p.textContent = "Use at least 12 characters, with uppercase and lowercase letters, a number, and a symbol. Do not use spaces.";
          const label = document.createElement("label");
          label.htmlFor = "newPassword";
          label.textContent = "New password";
          const input = document.createElement("input");
          input.id = "newPassword";
          input.type = "password";
          input.autocomplete = "new-password";
          const save = button("Save new password");
          save.addEventListener("click", async () => {
            const data = await post("/api/reset/password", { token: resetToken, password: input.value });
            if (!data.ok) {
              setMessage(data.message, "error");
              return;
            }
            resetToken = "";
            stage = "complete";
            render();
          });
          app.append(p, label, input, save);
        } else if (stage === "complete") {
          title.textContent = "Password changed";
          const p = document.createElement("p");
          p.textContent = "Your password has been changed. The recovery code can no longer be used.";
          const next = button("Continue to secure sign-in");
          next.addEventListener("click", () => go("/signin", "signin"));
          app.append(p, next);
        } else if (stage === "signin") {
          title.textContent = "Secure sign-in";
          const p = document.createElement("p");
          p.textContent = "Sign in on this hospital page only. A second verification step will follow.";
          const il = document.createElement("label");
          il.htmlFor = "identifier";
          il.textContent = "Email address";
          const identifier = document.createElement("input");
          identifier.id = "identifier";
          identifier.type = "email";
          identifier.autocomplete = "username";
          const pl = document.createElement("label");
          pl.htmlFor = "signinPassword";
          pl.textContent = "Password";
          const password = document.createElement("input");
          password.id = "signinPassword";
          password.type = "password";
          password.autocomplete = "current-password";
          const goButton = button("Continue to verification");
          goButton.addEventListener("click", async () => {
            const data = await post("/api/signin", { identifier: identifier.value.trim(), password: password.value });
            if (!data.ok) {
              setMessage(data.message, "error");
              return;
            }
            log("[mock MFA] Sign-in code for browser testing: " + data.mockMfaCode);
            stage = "mfa";
            render();
            setMessage("Next step: enter the verification code from the simulation log.", "success");
          });
          const reset = button("Reset password instead", "secondary");
          reset.addEventListener("click", () => go("/", "start"));
          app.append(p, il, identifier, pl, password, goButton, reset);
        } else if (stage === "mfa") {
          title.textContent = "Confirm sign-in";
          const p = document.createElement("p");
          p.textContent = "Enter the verification code from the simulated delivery log. This confirms it is this browser completing the sign-in.";
          const label = document.createElement("label");
          label.htmlFor = "mfa";
          label.textContent = "Verification code";
          const input = document.createElement("input");
          input.id = "mfa";
          input.inputMode = "numeric";
          input.autocomplete = "one-time-code";
          input.maxLength = 6;
          const verify = button("Confirm sign-in");
          verify.addEventListener("click", async () => {
            const data = await post("/api/mfa", { code: input.value.trim() });
            if (!data.ok) {
              setMessage(data.message, "error");
              return;
            }
            go("/account", "privacy");
          });
          app.append(p, label, input, verify);
        } else if (stage === "privacy") {
          title.textContent = "Accept the updated privacy statement";
          const p = document.createElement("p");
          p.textContent = "To continue with the appointment request, confirm that you accept the updated privacy statement.";
          const accept = button("Accept and continue");
          accept.addEventListener("click", async () => {
            const data = await post("/api/privacy", {});
            if (!data.ok) {
              setMessage(data.message, "error");
              return;
            }
            go("/appointment", "appointment");
            setMessage(data.message, "success");
          });
          app.append(p, accept);
        } else {
          title.textContent = "Confirm medication review appointment";
          const p = document.createElement("p");
          p.textContent = "Your privacy statement acceptance is recorded. Confirm this final step to request a medication dosage review appointment.";
          const confirm = button("Confirm appointment request");
          confirm.addEventListener("click", async () => {
            const data = await post("/api/appointment", {});
            setMessage(data.message, data.ok ? "success" : "error");
            if (data.ok) {
              confirm.disabled = true;
              confirm.textContent = "Appointment request confirmed";
            }
          });
          app.append(p, confirm);
        }
      }

      pauseButton.addEventListener("click", () => {
        paused = !paused;
        if (paused) {
          pauseButton.textContent = "Resume saved place";
          log("[recovery] Progress remains safely available in this browser session.");
        } else {
          pauseButton.textContent = "Pause and save place";
          log("[recovery] Resumed at the secure saved step.");
          render();
        }
      });

      window.addEventListener("popstate", () => {
        const paths = { "/":"start", "/reset":"code", "/signin":"signin", "/account":"privacy", "/appointment":"appointment" };
        stage = paths[location.pathname] || "start";
        restoreRecoveryState();
        render();
      });

      async function restoreRecoveryState() {
        const data = await post("/api/recovery/state", {});
        if (!data.ok) return;
        if ((stage === "code" || stage === "password") && data.recoveryStage !== "start") {
          stage = data.recoveryStage;
          resetToken = data.token || "";
          render();
          log("[recovery] Secure recovery progress restored for this browser session.");
        } else if ((stage === "code" || stage === "password") && data.recoveryStage === "start") {
          stage = "start";
          resetToken = "";
          render();
        }
      }

      render();
      restoreRecoveryState();
    })();
  </script>
</body>
</html>`;
}

async function httpsFetch(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const paths = ["/", "/reset", "/signin", "/account", "/appointment"];

    if (request.method === "GET" && paths.includes(url.pathname)) {
      const { session, isNew } = getSession(request, true);

      /*
        Protected UI routes also have server authorization. API authorization remains
        authoritative for all sensitive actions.
      */
      if (url.pathname === "/account" && !session!.authenticated) {
        const headers = secureHeaders();
        headers.set("Location", "/signin");
        if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
        return new Response(null, { status: 303, headers });
      }
      if (url.pathname === "/appointment" && (!session!.authenticated || !session!.privacyAccepted)) {
        const headers = secureHeaders();
        headers.set("Location", session!.authenticated ? "/account" : "/signin");
        if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
        return new Response(null, { status: 303, headers });
      }

      const stageByPath: Record<string, string> = {
        "/": "start",
        "/reset": "code",
        "/signin": "signin",
        "/account": session!.privacyAccepted ? "appointment" : "privacy",
        "/appointment": "appointment",
      };
      const nonce = randomHex(18);
      const headers = secureHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
      return new Response(page(nonce, session!.csrf, stageByPath[url.pathname]), { status: 200, headers });
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) {
      return await handleApi(request, url.pathname);
    }

    return new Response("Not found.", { status: 404, headers: secureHeaders() });
  } catch {
    return new Response("Service unavailable.", { status: 503, headers: secureHeaders() });
  }
}

function httpRedirect(request: Request): Response {
  const url = new URL(request.url);
  const knownPath = ["/", "/reset", "/signin", "/account", "/appointment"].includes(url.pathname) ||
    url.pathname.startsWith("/api/");
  const safePath = knownPath ? url.pathname : "/";
  const location = `https://localhost:${HTTPS_PORT}${safePath}${safePath === url.pathname ? url.search : ""}`;
  const headers = secureHeaders();
  headers.set("Location", location);
  return new Response(null, { status: 308, headers });
}

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

/* HTTPS safeguard: dedicated TLS listener plus an HTTP listener that only redirects to HTTPS. */
Bun.serve({
  port: HTTPS_PORT,
  tls: {
    cert: Bun.file(CERT_PATH),
    key: Bun.file(KEY_PATH),
  },
  fetch: httpsFetch,
});

Bun.serve({
  port: HTTP_PORT,
  fetch: httpRedirect,
});

console.log(`Secure recovery demo: https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirect listener: http://localhost:${HTTP_PORT} → HTTPS`);
