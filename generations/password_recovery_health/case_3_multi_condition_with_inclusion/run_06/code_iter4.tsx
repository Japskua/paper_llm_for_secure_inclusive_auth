
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

/*
  Password Recovery System
  - HTTPS / secure headers: Security Misconfiguration requirements
  - Sessions, CSRF, ownership: Broken Access Control requirements
  - Escaped client rendering/CSP: Injection (XSS) requirements
  - Random reset records: reset-token requirements
  - MFA, password hashing, throttling: Authentication requirements
  - Fixed same-origin navigation only: SSRF/open-redirect requirements
  - Focused progress, pause/resume, help: ADHD inclusivity requirements
*/

type ResetRecord = {
  token: string;
  expiresAt: number;
  used: boolean;
};

type AttemptState = {
  attempts: number;
  windowStart: number;
  lockedUntil: number;
};

type RecoveryState = "request" | "code" | "mfa" | "password" | "finished";

type Session = {
  id: string;
  csrf: string;
  reset?: ResetRecord;
  verifiedToken?: string;
  mfaSent?: boolean;
  mfaVerified?: boolean;
  attempts: Record<string, AttemptState>;
};

const sessions = new Map<string, Session>();
const crossSessionAttempts = new Map<string, AttemptState>();
let storedPasswordHash = "";

const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;
const RESET_LIFETIME_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const MFA_CODE = "246810";
const DELIVERY_SESSION_LIMIT = 5;
const DELIVERY_CROSS_SESSION_LIMIT = 20;

/*
  A deployment may explicitly configure a header that its trusted reverse proxy
  strips from public traffic and sets itself. Without that deployment guarantee,
  request headers are not trustworthy, so the conservative shared "global"
  bucket protects all sessions instead of trusting attacker-controlled headers.
*/
const TRUSTED_CLIENT_ID_HEADER = process.env.TRUSTED_CLIENT_ID_HEADER?.toLowerCase() || "";

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const piece of cookie.split(";")) {
    const index = piece.indexOf("=");
    if (index > -1) {
      result[piece.slice(0, index).trim()] = decodeURIComponent(piece.slice(index + 1).trim());
    }
  }
  return result;
}

function newSession(): Session {
  const session: Session = {
    id: randomToken(32),
    csrf: randomToken(32),
    attempts: {},
  };
  sessions.set(session.id, session);
  return session;
}

function sessionFor(request: Request, create = false): Session | undefined {
  const sid = parseCookies(request).recovery_session;
  const existing = sid ? sessions.get(sid) : undefined;
  return existing || (create ? newSession() : undefined);
}

function secureCookie(session: Session): string {
  return `recovery_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}

/* CSP allows only same-origin JavaScript served by /app.js. */
function securityHeaders(): Headers {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
      "frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
  });
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) {
    for (const [key, value] of new Headers(extra)) headers.set(key, value);
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function genericFailure(status = 400): Response {
  return json({ ok: false, message: "We could not complete that step. Please check the code and try again." }, status);
}

async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* CSRF/access-control guard used by every state-changing route. */
async function protectedRequest(request: Request): Promise<{ session: Session; body: Record<string, unknown> } | Response> {
  const session = sessionFor(request);
  if (!session) return genericFailure(403);
  const csrf = request.headers.get("x-csrf-token");
  if (!csrf || csrf.length !== session.csrf.length || csrf !== session.csrf) return genericFailure(403);
  const body = await bodyOf(request);
  if (!body) return genericFailure();
  return { session, body };
}

/* Session-scoped authentication rate limiting. */
function permitted(session: Session, name: string, maxAttempts: number): boolean {
  const now = Date.now();
  let entry = session.attempts[name];
  if (!entry || now - entry.windowStart > ATTEMPT_WINDOW_MS) {
    entry = { attempts: 0, windowStart: now, lockedUntil: 0 };
    session.attempts[name] = entry;
  }
  if (entry.lockedUntil > now) return false;
  return true;
}

function failedAttempt(session: Session, name: string, maxAttempts: number): void {
  const entry = session.attempts[name] || { attempts: 0, windowStart: Date.now(), lockedUntil: 0 };
  entry.attempts++;
  if (entry.attempts >= maxAttempts) {
    entry.lockedUntil = Date.now() + LOCK_MS;
    entry.attempts = 0;
  }
  session.attempts[name] = entry;
  console.log(`[security] ${name} session attempt recorded; no account information logged`);
}

function clearAttempts(session: Session, name: string): void {
  delete session.attempts[name];
}

function trustworthyClientKey(request: Request): string {
  if (TRUSTED_CLIENT_ID_HEADER) {
    const value = request.headers.get(TRUSTED_CLIENT_ID_HEADER)?.trim() || "";
    if (/^[A-Za-z0-9._:-]{1,128}$/.test(value)) return `client:${value}`;
  }
  return "global";
}

function crossState(request: Request, name: string): AttemptState {
  const key = `${name}:${trustworthyClientKey(request)}`;
  const now = Date.now();
  let entry = crossSessionAttempts.get(key);
  if (!entry || now - entry.windowStart > ATTEMPT_WINDOW_MS) {
    entry = { attempts: 0, windowStart: now, lockedUntil: 0 };
    crossSessionAttempts.set(key, entry);
  }
  return entry;
}

function crossPermitted(request: Request, name: string): boolean {
  return crossState(request, name).lockedUntil <= Date.now();
}

function crossFailedAttempt(request: Request, name: string, maxAttempts: number): void {
  const entry = crossState(request, name);
  entry.attempts++;
  if (entry.attempts >= maxAttempts) {
    entry.lockedUntil = Date.now() + LOCK_MS;
    entry.attempts = 0;
  }
  console.log(`[security] ${name} cross-session attempt recorded; no account or token details logged`);
}

function clearCrossAttempts(request: Request, name: string): void {
  const key = `${name}:${trustworthyClientKey(request)}`;
  crossSessionAttempts.delete(key);
}

function authenticationPermitted(request: Request, session: Session, name: string): boolean {
  return permitted(session, name, 5) && crossPermitted(request, name);
}

function authenticationFailed(request: Request, session: Session, name: string): void {
  failedAttempt(session, name, 5);
  crossFailedAttempt(request, name, 20);
}

function authenticationSucceeded(request: Request, session: Session, name: string): void {
  clearAttempts(session, name);
  clearCrossAttempts(request, name);
}

/*
  Recovery-delivery throttling is intentionally shared by both request routes.
  Successful sends consume a session and cross-session allowance before a fresh
  token is created, preventing route switching from bypassing the limit.
*/
function deliveryRateState(session: Session): AttemptState {
  const now = Date.now();
  let entry = session.attempts["recovery-delivery"];
  if (!entry || now - entry.windowStart > ATTEMPT_WINDOW_MS) {
    entry = { attempts: 0, windowStart: now, lockedUntil: 0 };
    session.attempts["recovery-delivery"] = entry;
  }
  return entry;
}

function deliveryPermitted(request: Request, session: Session): boolean {
  const sessionEntry = deliveryRateState(session);
  const crossEntry = crossState(request, "recovery-delivery");
  const now = Date.now();
  return sessionEntry.lockedUntil <= now &&
    crossEntry.lockedUntil <= now &&
    sessionEntry.attempts < DELIVERY_SESSION_LIMIT &&
    crossEntry.attempts < DELIVERY_CROSS_SESSION_LIMIT;
}

function recordDeliveryRequest(request: Request, session: Session): void {
  const now = Date.now();
  const sessionEntry = deliveryRateState(session);
  const crossEntry = crossState(request, "recovery-delivery");

  sessionEntry.attempts++;
  crossEntry.attempts++;

  if (sessionEntry.attempts >= DELIVERY_SESSION_LIMIT) {
    sessionEntry.lockedUntil = now + LOCK_MS;
  }
  if (crossEntry.attempts >= DELIVERY_CROSS_SESSION_LIMIT) {
    crossEntry.lockedUntil = now + LOCK_MS;
  }
}

function resetIsValid(session: Session): boolean {
  const reset = session.reset;
  return !!reset &&
    !reset.used &&
    reset.expiresAt > Date.now() &&
    session.verifiedToken === reset.token;
}

/*
  Server-derived recovery state. The server is authoritative: browser storage
  is only a convenience and never grants access to a later recovery step.
*/
function recoveryStatus(session: Session): { state: RecoveryState; issue?: string; message?: string } {
  const reset = session.reset;
  if (!reset) {
    return {
      state: "request",
      message: "Start with step 1 when you are ready.",
    };
  }
  if (reset.used) {
    return {
      state: "finished",
      message: "This recovery task is complete.",
    };
  }
  if (reset.expiresAt <= Date.now()) {
    return {
      state: "request",
      issue: "expired",
      message: "Your recovery progress has expired. Return to step 1 and request a fresh code.",
    };
  }
  if (session.verifiedToken !== reset.token) {
    return {
      state: "code",
      message: "Your recovery code is ready. Enter it here, or request another code if needed.",
    };
  }
  if (!session.mfaVerified) {
    return {
      state: "mfa",
      message: "Your recovery code is confirmed. Next, confirm your security code.",
    };
  }
  return {
    state: "password",
    message: "Your security code is confirmed. You can now choose a new password.",
  };
}

function validPassword(password: string): boolean {
  return password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9\s]/.test(password) &&
    !/\s/.test(password);
}

function createReplacementReset(session: Session): string {
  const token = randomToken(32);
  session.reset = { token, expiresAt: Date.now() + RESET_LIFETIME_MS, used: false };
  session.verifiedToken = undefined;
  session.mfaSent = false;
  session.mfaVerified = false;
  return token;
}

async function api(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/session" && request.method === "GET") {
    const existing = sessionFor(request);
    const session = existing || newSession();
    const recovery = recoveryStatus(session);
    const headers = new Headers();
    if (!existing) headers.set("Set-Cookie", secureCookie(session));
    return json({
      ok: true,
      csrf: session.csrf,
      recoveryState: recovery.state,
      recoveryIssue: recovery.issue || null,
      recoveryMessage: recovery.message || null,
      hasRecoverableCode: recovery.state === "code",
    }, 200, headers);
  }

  /*
    Testing-only, session-authoritative restoration of a simulated delivery.
    The token is never selected by an identifier from the browser and is only
    returned for the owning active session while it is still at code step.
  */
  if (pathname === "/api/recovery/mock-delivery" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session } = guarded;
    const recovery = recoveryStatus(session);

    if (recovery.state !== "code" || !session.reset) {
      return json({
        ok: false,
        message: "There is no active recovery code to restore. Return to step 1 if you need a fresh code.",
      }, 403);
    }

    return json({
      ok: true,
      mockDeliveryToken: session.reset.token,
      message: "Your active practice recovery code was restored for this browser session.",
    });
  }

  /*
    Protected restart rotates both the opaque session identifier and CSRF token.
    It is deliberately permitted only after a completed recovery state.
  */
  if (pathname === "/api/recovery/restart" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session } = guarded;

    if (!session.reset?.used) {
      return json({ ok: false, message: "Restart is available after the current recovery is complete." }, 403);
    }

    sessions.delete(session.id);
    const replacement = newSession();
    return json(
      { ok: true, csrf: replacement.csrf, message: "A fresh recovery session is ready." },
      200,
      { "Set-Cookie": secureCookie(replacement) },
    );
  }

  if (pathname === "/api/recovery/request" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;

    const contact = typeof body.contact === "string" ? body.contact.trim() : "";
    if (contact.length < 3 || contact.length > 254) return genericFailure();
    if (!deliveryPermitted(request, session)) return genericFailure(429);

    /* Record the successful request before issuing the random single-use token. */
    recordDeliveryRequest(request, session);
    const token = createReplacementReset(session);
    return json({
      ok: true,
      message: "If an eligible account matches those details, a recovery message has been prepared.",
      mockDeliveryToken: token,
    });
  }

  if (pathname === "/api/recovery/request-another" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session } = guarded;

    if (!session.reset || session.reset.used || session.reset.expiresAt <= Date.now()) {
      return json({
        ok: false,
        message: "This recovery progress is unavailable or expired. Return to step 1 and request a fresh code.",
      }, 403);
    }
    if (!deliveryPermitted(request, session)) return genericFailure(429);

    /* This successful replacement shares the same delivery rate-limit bucket. */
    recordDeliveryRequest(request, session);
    const token = createReplacementReset(session);
    return json({
      ok: true,
      message: "A new recovery code has been prepared. Any earlier recovery code no longer works.",
      mockDeliveryToken: token,
    });
  }

  if (pathname === "/api/reset/verify" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!authenticationPermitted(request, session, "reset-verify")) return genericFailure(429);
    const token = typeof body.token === "string" ? body.token : "";
    const reset = session.reset;

    if (!/^[A-Za-z0-9_-]{43}$/.test(token) || !reset || reset.used ||
      reset.expiresAt <= Date.now() || token !== reset.token) {
      authenticationFailed(request, session, "reset-verify");
      return genericFailure();
    }

    session.verifiedToken = token;
    authenticationSucceeded(request, session, "reset-verify");
    console.log("[security] reset token verified for its owning session");
    return json({ ok: true, message: "Code confirmed. Next, confirm your security code." });
  }

  if (pathname === "/api/mfa/send" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session } = guarded;
    if (!resetIsValid(session)) return genericFailure(403);

    session.mfaSent = true;
    session.mfaVerified = false;
    return json({
      ok: true,
      message: "A security code has been prepared for this practice session.",
      mockMfaCode: MFA_CODE,
    });
  }

  if (pathname === "/api/mfa/verify" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!authenticationPermitted(request, session, "mfa-verify")) return genericFailure(429);

    const code = typeof body.code === "string" ? body.code : "";
    if (!resetIsValid(session) || !session.mfaSent || code !== MFA_CODE) {
      authenticationFailed(request, session, "mfa-verify");
      return genericFailure();
    }

    session.mfaVerified = true;
    authenticationSucceeded(request, session, "mfa-verify");
    console.log("[security] MFA confirmed for reset-owning session");
    return json({ ok: true, message: "Security code confirmed. You can now choose a new password." });
  }

  if (pathname === "/api/password/change" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    const password = typeof body.password === "string" ? body.password : "";

    if (!resetIsValid(session) || !session.mfaVerified) return genericFailure(403);
    if (!validPassword(password)) {
      return json({ ok: false, message: "Use 12 or more characters with upper and lower case letters, a number, and a symbol." });
    }

    storedPasswordHash = await (Bun.password as any).hash(password, {
      algorithm: "bcrypt",
      cost: 10,
    });
    session.reset!.used = true;
    session.verifiedToken = undefined;
    session.mfaVerified = false;
    console.log("[security] password reset completed; bcrypt hash stored, no password logged");
    return json({ ok: true, message: "Your password has been changed." });
  }

  if (pathname === "/api/login" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!authenticationPermitted(request, session, "login")) return genericFailure(429);

    const password = typeof body.password === "string" ? body.password : "";
    const valid = !!storedPasswordHash && await (Bun.password as any).verify(password, storedPasswordHash);
    if (!valid) {
      authenticationFailed(request, session, "login");
      return json({ ok: false, message: "The sign-in details could not be confirmed." }, 401);
    }

    authenticationSucceeded(request, session, "login");
    console.log("[security] generic login success");
    return json({ ok: true, message: "Sign-in confirmed." });
  }

  return json({ ok: false, message: "Not found." }, 404);
}

const clientJavaScript = String.raw`
(() => {
  "use strict";

  let csrf = "";
  let currentStep = Number(localStorage.getItem("recovery-step") || "1");
  let lastToken = "";
  let hasRecoverableCode = false;

  const stateSteps = { request: 1, code: 2, mfa: 3, password: 4, finished: 5 };
  const $ = (id) => document.getElementById(id);
  const steps = Array.from(document.querySelectorAll(".step"));
  const logList = $("logList");

  // XSS requirement: dynamic strings always use textContent, never innerHTML.
  function audit(message) {
    console.log(message);
    const li = document.createElement("li");
    li.textContent = message;
    logList.appendChild(li);
    logList.scrollTop = logList.scrollHeight;
  }

  function status(id, message, bad) {
    const element = $(id);
    element.textContent = message;
    element.className = "status" + (bad ? " error" : "");
  }

  function showStep(number) {
    currentStep = Math.max(1, Math.min(5, number));
    localStorage.setItem("recovery-step", String(currentStep));

    steps.forEach((section) => {
      section.hidden = Number(section.dataset.step) !== currentStep;
    });

    document.querySelectorAll("#progress li").forEach((item) => {
      const n = Number(item.dataset.n);
      item.classList.toggle("active", n === currentStep);
      item.classList.toggle("done", n < currentStep);
    });

    if (currentStep === 5) {
      $("orientation").textContent = "You have finished the recovery steps. Your new password is ready to use.";
    } else if (currentStep === 2) {
      $("orientation").textContent = "You are on step 2 of 5. You can pause safely. If you need a fresh code, select “Request another recovery code” on this step.";
    } else {
      $("orientation").textContent = "You are on step " + currentStep + " of 5. You can pause at any time; your place is saved on this device.";
    }

    const focus = document.querySelector('.step[data-step="' + currentStep + '"] h2');
    if (focus) focus.setAttribute("tabindex", "-1");
  }

  async function call(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(payload)
    });
    try {
      return await response.json();
    } catch {
      return { ok: false, message: "The secure recovery service could not complete that step." };
    }
  }

  function passwordLooksStrong(value) {
    return value.length >= 12 && value.length <= 128 && /[a-z]/.test(value) &&
      /[A-Z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9\s]/.test(value) && !/\s/.test(value);
  }

  function recordResetDelivery(token, replacement, restored) {
    lastToken = token;
    hasRecoverableCode = true;
    $("token").value = "";
    $("openLink").hidden = false;
    const prefix = restored
      ? "Restored simulated reset delivery token (testing only): "
      : replacement
        ? "Replacement simulated reset delivery token (testing only): "
        : "Simulated reset delivery token (testing only): ";
    audit(prefix + lastToken);
  }

  function returnToStepOne(message) {
    lastToken = "";
    hasRecoverableCode = false;
    $("openLink").hidden = true;
    showStep(1);
    status("requestStatus", message, true);
  }

  $("requestForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const contact = $("contact").value.trim();
    if (contact.length < 3) {
      return status("requestStatus", "Please enter an email address or phone number.", true);
    }

    const result = await call("/api/recovery/request", { contact });
    status("requestStatus", result.message, !result.ok);
    if (result.ok) {
      recordResetDelivery(result.mockDeliveryToken, false, false);
      showStep(2);
    }
  });

  $("openLink").addEventListener("click", () => {
    if (!lastToken) return;
    // Same-origin fixed route only; no arbitrary outgoing redirect is possible.
    location.assign("/recovery?reset=" + encodeURIComponent(lastToken));
  });

  $("requestAnother").addEventListener("click", async () => {
    if (!hasRecoverableCode) {
      returnToStepOne("This recovery progress is unavailable. Please request a fresh code in step 1.");
      return;
    }

    const result = await call("/api/recovery/request-another", {});
    status("verifyStatus", result.message, !result.ok);
    if (result.ok) {
      recordResetDelivery(result.mockDeliveryToken, true, false);
      audit("Earlier recovery code invalidated. Use the new practice token.");
    } else if (/unavailable|expired/i.test(result.message || "")) {
      audit("Recovery progress is unavailable or expired. Returning to step 1 for a fresh code.");
      returnToStepOne("Your earlier recovery progress is unavailable or expired. Request a fresh code below.");
    }
  });

  $("verifyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const token = $("token").value.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
      return status("verifyStatus", "Please enter the complete recovery code.", true);
    }

    const result = await call("/api/reset/verify", { token });
    status("verifyStatus", result.message, !result.ok);
    if (result.ok) showStep(3);
  });

  $("sendMfa").addEventListener("click", async () => {
    const result = await call("/api/mfa/send", {});
    status("mfaStatus", result.message, !result.ok);
    if (result.ok) audit("Simulated MFA code (testing only): " + result.mockMfaCode);
  });

  $("mfaForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = $("mfa").value.trim();
    if (!/^\d{6}$/.test(code)) {
      return status("mfaStatus", "Please enter the six-digit security code.", true);
    }

    const result = await call("/api/mfa/verify", { code });
    status("mfaStatus", result.message, !result.ok);
    if (result.ok) showStep(4);
  });

  $("passwordForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = $("password").value;
    const confirmation = $("confirmPassword").value;

    if (!passwordLooksStrong(password)) {
      return status("passwordStatus", "Use 12 or more characters with upper and lower case letters, a number, and a symbol.", true);
    }
    if (password !== confirmation) {
      return status("passwordStatus", "The two passwords do not match. Please try again.", true);
    }

    const result = await call("/api/password/change", { password });
    $("password").value = "";
    $("confirmPassword").value = "";
    status("passwordStatus", result.message, !result.ok);

    if (result.ok) {
      hasRecoverableCode = false;
      audit("Password reset completed safely.");
      showStep(5);
    }
  });

  $("restart").addEventListener("click", async () => {
    $("restart").disabled = true;
    const result = await call("/api/recovery/restart", {});
    if (result.ok) {
      csrf = result.csrf;
      lastToken = "";
      hasRecoverableCode = false;
      localStorage.removeItem("recovery-step");
      location.assign("/");
      return;
    }
    $("restart").disabled = false;
    audit(result.message || "A fresh recovery session could not be started. Please try again.");
  });

  /*
    Reconcile device-only progress with server authority on startup.
    A saved later step never bypasses reset, MFA, or password authorization.
  */
  function reconcileSession(session) {
    csrf = session.csrf;
    hasRecoverableCode = !!session.hasRecoverableCode;

    const serverStep = stateSteps[session.recoveryState] || 1;
    const savedStep = currentStep;
    const fromLink = new URLSearchParams(location.search).get("reset");

    if (fromLink) {
      $("token").value = fromLink;
      showStep(2);
      audit("Recovery link opened. Confirming its code for this browser session.");
      return "link";
    }

    if (session.recoveryIssue === "expired") {
      audit("Your saved recovery progress has expired. Return to step 1 and request a fresh code.");
      returnToStepOne(session.recoveryMessage || "Your recovery progress has expired. Request a fresh code below.");
      return "done";
    }

    if (savedStep !== serverStep) {
      if (serverStep < savedStep) {
        audit("Saved recovery progress was unavailable, expired, or replaced. We returned you to the earliest available step.");
      } else {
        audit("Your confirmed recovery progress was restored from the secure service.");
      }
    }

    showStep(serverStep);

    if (serverStep === 1 && savedStep > 1) {
      status("requestStatus", "Your earlier recovery progress is unavailable. Please request a fresh code.", true);
    } else if (serverStep === 2) {
      audit("Recovery code step restored. Enter your code or request another code if you need a fresh one.");
      if (savedStep > 2) {
        status("verifyStatus", "The earlier recovery code was replaced or is no longer available. Enter the current code, or request a fresh code.", true);
      }
      return "restore-delivery";
    } else if (session.recoveryMessage) {
      const statusId = serverStep === 3 ? "mfaStatus" : serverStep === 4 ? "passwordStatus" : null;
      if (statusId) status(statusId, session.recoveryMessage, false);
    }

    return "done";
  }

  async function restoreMockDelivery() {
    const result = await call("/api/recovery/mock-delivery", {});
    if (result.ok && typeof result.mockDeliveryToken === "string") {
      recordResetDelivery(result.mockDeliveryToken, false, true);
      return;
    }
    audit("The earlier practice recovery code could not be restored. You may request another code.");
  }

  async function start() {
    const sessionResponse = await fetch("/api/session", {
      credentials: "same-origin",
      cache: "no-store"
    });
    if (!sessionResponse.ok) throw new Error("Session unavailable");

    const session = await sessionResponse.json();
    const reconciliation = reconcileSession(session);

    if (reconciliation === "link") {
      const fromLink = new URLSearchParams(location.search).get("reset");
      const result = await call("/api/reset/verify", { token: fromLink });
      status("verifyStatus", result.message, !result.ok);
      if (result.ok) showStep(3);
      history.replaceState({}, "", "/recovery");
    } else if (reconciliation === "restore-delivery") {
      await restoreMockDelivery();
    }
  }

  start().catch(() => {
    audit("The secure recovery service is temporarily unavailable. Please try again.");
    returnToStepOne("Recovery progress is unavailable right now. Return to step 1 and try requesting a fresh code.");
  });
})();
`;

function appScript(): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/javascript; charset=utf-8");
  return new Response(clientJavaScript, { headers });
}

function page(): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "text/html; charset=utf-8");

  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style>
:root { color-scheme: light; --blue:#075a9c; --ink:#172331; --soft:#eef5fa; --line:#b9cad7; --good:#086d42; --warn:#934100; }
* { box-sizing:border-box; }
body { margin:0; font:18px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--ink); background:#f6f9fb; }
header { background:#fff; border-bottom:4px solid var(--blue); }
.wrap { width:min(760px, calc(100% - 32px)); margin:auto; }
header .wrap { padding:22px 0 18px; }
h1 { font-size:1.65rem; margin:0; }
h2 { font-size:1.28rem; margin-top:0; }
.subtitle { margin:4px 0 0; color:#405367; }
main { padding:28px 0 40px; }
.progress { display:flex; list-style:none; padding:0; margin:0 0 24px; gap:6px; flex-wrap:wrap; }
.progress li { border:1px solid var(--line); border-radius:20px; padding:5px 10px; font-size:.83rem; background:#fff; }
.progress li.active { background:var(--blue); color:#fff; border-color:var(--blue); font-weight:700; }
.progress li.done { border-color:var(--good); color:var(--good); }
.card, details, .logs { background:#fff; border:1px solid var(--line); border-radius:10px; padding:22px; box-shadow:0 1px 2px #1224; }
.step[hidden] { display:none; }
p { max-width:65ch; }
label { display:block; font-weight:700; margin:16px 0 5px; }
input { display:block; width:100%; max-width:520px; padding:12px; border:2px solid #71889b; border-radius:6px; font:inherit; }
input:focus, button:focus, summary:focus { outline:3px solid #f3b83f; outline-offset:3px; }
button { margin-top:18px; padding:11px 17px; border:0; border-radius:6px; background:var(--blue); color:#fff; font:inherit; font-weight:700; cursor:pointer; }
button.secondary { background:#e4edf3; color:#152a3a; margin-left:8px; }
button:disabled { opacity:.6; cursor:not-allowed; }
.notice { padding:12px 14px; background:var(--soft); border-left:5px solid var(--blue); }
.status { min-height:28px; font-weight:700; color:var(--good); }
.error { color:#9b250d; }
small { color:#405367; }
details { margin-top:18px; }
summary { font-weight:700; cursor:pointer; }
.logs { margin-top:18px; }
#logList { margin:8px 0 0; padding-left:22px; font:14px/1.4 ui-monospace,monospace; max-height:150px; overflow:auto; }
footer { color:#405367; font-size:.9rem; margin-top:20px; }
@media (max-width:520px) {
  body { font-size:17px; }
  .card { padding:17px; }
  button.secondary { margin-left:0; }
}
</style>
<script src="/app.js" defer></script>
</head>
<body>
<header>
  <div class="wrap">
    <h1>Hospital account recovery</h1>
    <p class="subtitle">A calm, guided way to reset your password</p>
  </div>
</header>
<main class="wrap">
<nav aria-label="Recovery progress">
  <ol class="progress" id="progress">
    <li data-n="1">1. Request</li>
    <li data-n="2">2. Recovery code</li>
    <li data-n="3">3. Security code</li>
    <li data-n="4">4. New password</li>
    <li data-n="5">5. Finished</li>
  </ol>
</nav>

<div class="notice" id="orientation">You are on step 1 of 5. You can pause at any time; your place is saved on this device.</div>

<section class="card step" data-step="1">
  <h2>Request a recovery code</h2>
  <p>Enter the email address or phone number you use for your hospital account. We will give the same response whether or not an account is found, to protect your privacy.</p>
  <form id="requestForm" novalidate>
    <label for="contact">Email address or phone number</label>
    <input id="contact" name="contact" autocomplete="email" inputmode="email" maxlength="254" required>
    <small>Use your own contact detail. Never enter a password here.</small><br>
    <button type="submit">Request recovery code</button>
  </form>
  <p class="status" id="requestStatus" aria-live="polite"></p>
  <button id="openLink" class="secondary" type="button" hidden>Open simulated recovery link</button>
</section>

<section class="card step" data-step="2" hidden>
  <h2>Confirm your recovery code</h2>
  <p>Use the recovery link from the practice delivery, or enter the code manually. The code is shown only in the browser console and the activity log for this demonstration.</p>
  <form id="verifyForm" novalidate>
    <label for="token">Recovery code</label>
    <input id="token" name="token" autocomplete="one-time-code" spellcheck="false" maxlength="80" required>
    <button type="submit">Confirm recovery code</button>
  </form>
  <button id="requestAnother" class="secondary" type="button">Request another recovery code</button>
  <p><small>If you paused or cannot find the earlier code, request another one here. It works in this same browser session and makes the earlier code stop working.</small></p>
  <p class="status" id="verifyStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="3" hidden>
  <h2>Confirm your security code</h2>
  <p>One more short check keeps your account safe. Select “Send security code”, then use the practice code from the activity log.</p>
  <button id="sendMfa" type="button">Send security code</button>
  <form id="mfaForm" novalidate>
    <label for="mfa">Security code</label>
    <input id="mfa" name="mfa" autocomplete="one-time-code" inputmode="numeric" maxlength="6" required>
    <button type="submit">Confirm security code</button>
  </form>
  <p class="status" id="mfaStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="4" hidden>
  <h2>Choose a new password</h2>
  <p>Create a password with at least 12 characters, an uppercase letter, lowercase letter, number, and symbol. It is not shown or saved in this page.</p>
  <form id="passwordForm" novalidate>
    <label for="password">New password</label>
    <input id="password" type="password" autocomplete="new-password" maxlength="128" required>
    <label for="confirmPassword">Confirm new password</label>
    <input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required>
    <button type="submit">Change password safely</button>
  </form>
  <p class="status" id="passwordStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="5" hidden>
  <h2>Password changed</h2>
  <p>Your recovery task is complete. You can now return to the hospital sign-in page and accept the updated privacy conditions.</p>
  <button id="restart" type="button">Start another recovery</button>
</section>

<details open>
  <summary>Help and safe sign-in reminders</summary>
  <p>Take one step at a time. There is no countdown. If you pause, return here on this device and the secure service will return you to the first valid step. On the recovery-code step, you may request another code if you need a fresh start.</p>
  <ul>
    <li>Hospital staff will never ask you to share a password or security code.</li>
    <li>Check that the address begins with <strong>https://localhost</strong> before entering a code.</li>
    <li>If something does not look right, stop and contact your hospital through its known phone number.</li>
  </ul>
</details>

<section class="logs" aria-label="Activity logs">
  <h2>Logs</h2>
  <p><small>Practice delivery and security events appear here without private account details.</small></p>
  <ul id="logList" aria-live="polite"></ul>
</section>

<footer>Recovery progress is saved only in this browser. There are no automatic timeouts on this page.</footer>
</main>
</body>
</html>`, { headers });
}

async function handleHttps(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (request.method === "GET" && url.pathname === "/app.js") return appScript();
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery")) return page();
    return json({ ok: false, message: "Not found." }, 404);
  } catch {
    return json({ ok: false, message: "The service could not complete that request." }, 500);
  }
}

// HTTPS requirement: mkcert files are deliberately loaded from the prescribed paths.
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

Bun.serve({
  port: HTTPS_PORT,
  tls: { cert, key },
  fetch: handleHttps,
});

// Plain HTTP has no application routes and always performs a fixed HTTPS redirect.
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const incoming = new URL(request.url);
    const location = `https://localhost:${HTTPS_PORT}${incoming.pathname}${incoming.search}`;
    return new Response(null, {
      status: 308,
      headers: {
        Location: location,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});

console.log(`Secure recovery service running at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirects to HTTPS at http://localhost:${HTTP_PORT}`);
