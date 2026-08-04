
import { randomBytes, createHash } from "node:crypto";

/*
 * Password Recovery System
 * Single-file Bun HTTPS server and vanilla HTML SPA.
 * Run with: bun app.ts
 */

type Stage = "request" | "tokenVerified" | "passwordSet" | "mfaVerified" | "privacyAccepted";

type AttemptBucket = {
  count: number;
  startedAt: number;
};

type IpRateBucket = AttemptBucket & {
  expiresAt: number;
};

type RecoveryRecord = {
  tokenDigest: string;
  expiresAt: number;
  used: boolean;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  stage: Stage;
  recovery?: RecoveryRecord;
  passwordHash?: string;
  mfaCode?: string;
  privacyAccepted: boolean;
  attempts: Record<string, AttemptBucket>;
};

const sessions = new Map<string, Session>();

// Requirement task: bounded server-side limiter is independent of browser sessions.
const ipRateLimits = new Map<string, IpRateBucket>();
const MAX_IP_RATE_BUCKETS = 10_000;

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_MAX_AGE_SECONDS = 30 * 60;
const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;

let server: any;

function randomOpaqueValue(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) {
    result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return result === 0;
}

function createSession(): Session {
  return {
    id: randomOpaqueValue(32),
    csrf: randomOpaqueValue(32),
    createdAt: Date.now(),
    stage: "request",
    privacyAccepted: false,
    attempts: {},
  };
}

function parseCookies(request: Request): Record<string, string> {
  const header = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of header.split(";")) {
    const separator = item.indexOf("=");
    if (separator > 0) {
      const key = item.slice(0, separator).trim();
      const value = item.slice(separator + 1).trim();
      result[key] = value;
    }
  }
  return result;
}

function getSession(request: Request, create = false): { session?: Session; isNew: boolean } {
  const sessionId = parseCookies(request).recovery_session;
  const session = sessionId ? sessions.get(sessionId) : undefined;

  if (session && Date.now() - session.createdAt < SESSION_MAX_AGE_SECONDS * 1000) {
    return { session, isNew: false };
  }

  if (sessionId) sessions.delete(sessionId);
  if (!create) return { isNew: false };

  const newSession = createSession();
  sessions.set(newSession.id, newSession);
  return { session: newSession, isNew: true };
}

function sessionCookie(session: Session): string {
  // Requirement 1: opaque, Secure, HttpOnly, SameSite=Strict session cookie.
  return `recovery_session=${session.id}; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return map[character];
  });
}

function securityHeaders(nonce: string): Headers {
  // Requirement 3: strict HTTPS browser protections and no third-party sources.
  const headers = new Headers();
  headers.set(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "img-src 'none'",
      "font-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("X-XSS-Protection", "0");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function jsonResponse(body: object, status = 200): Response {
  const headers = securityHeaders(randomOpaqueValue(16));
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function requireCsrf(request: Request): { session?: Session; error?: Response } {
  // Requirement 1: every state-changing endpoint validates the session-specific CSRF token.
  const { session } = getSession(request, false);
  if (!session) {
    return { error: jsonResponse({ ok: false, message: "Your secure session has ended. Please start again." }, 401) };
  }

  const requestOrigin = request.headers.get("origin");
  const expectedOrigin = new URL(request.url).origin;
  const csrf = request.headers.get("x-csrf-token") || "";

  if (requestOrigin !== expectedOrigin || !safeEqual(csrf, session.csrf)) {
    return { error: jsonResponse({ ok: false, message: "This request could not be verified. Please refresh and try again." }, 403) };
  }

  return { session };
}

function throttled(session: Session, action: string, maximum: number): boolean {
  const now = Date.now();
  const bucket = session.attempts[action];

  if (!bucket || now - bucket.startedAt > ATTEMPT_WINDOW_MS) {
    session.attempts[action] = { count: 1, startedAt: now };
    return false;
  }

  bucket.count += 1;
  return bucket.count > maximum;
}

/*
 * Requirement task: use Bun's direct TCP peer address, not X-Forwarded-For,
 * Forwarded, or another attacker-controlled request header. This server is a
 * direct TLS listener, so the peer is the trusted client IP source.
 */
function trustedClientIp(request: Request): string {
  try {
    const peer = server?.requestIP(request);
    if (peer && typeof peer.address === "string" && peer.address.length > 0) {
      return peer.address;
    }
  } catch {
    // A conservative shared fallback prevents bypass if peer lookup is unavailable.
  }
  return "unavailable-peer";
}

function cleanupIpRateLimits(now: number): void {
  for (const [key, bucket] of ipRateLimits) {
    if (bucket.expiresAt <= now) ipRateLimits.delete(key);
  }
}

/*
 * Requirement task: a bounded, expiring global action/IP bucket prevents a
 * fresh cookie or a new session from resetting sensitive endpoint limits.
 */
function ipThrottled(request: Request, action: string, maximum: number): boolean {
  const now = Date.now();
  cleanupIpRateLimits(now);

  const key = `${action}\u0000${trustedClientIp(request)}`;
  const existing = ipRateLimits.get(key);

  if (!existing) {
    if (ipRateLimits.size >= MAX_IP_RATE_BUCKETS) {
      let oldestKey: string | undefined;
      let oldestExpiry = Number.POSITIVE_INFINITY;
      for (const [candidateKey, bucket] of ipRateLimits) {
        if (bucket.expiresAt < oldestExpiry) {
          oldestExpiry = bucket.expiresAt;
          oldestKey = candidateKey;
        }
      }
      if (oldestKey) ipRateLimits.delete(oldestKey);
    }

    ipRateLimits.set(key, {
      count: 1,
      startedAt: now,
      expiresAt: now + ATTEMPT_WINDOW_MS,
    });
    return false;
  }

  existing.count += 1;
  return existing.count > maximum;
}

function passwordPolicyError(password: string): string | null {
  // Requirement 4: server-side strong password policy.
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/[0-9]/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include a symbol.";
  return null;
}

async function requestJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) return null;
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function stageRoute(stage: Stage): string {
  if (stage === "tokenVerified") return "password";
  if (stage === "passwordSet") return "mfa";
  if (stage === "mfaVerified") return "privacy";
  if (stage === "privacyAccepted") return "complete";
  return "recover";
}

function page(session: Session, nonce: string): string {
  // Dynamic values are server-controlled random/enumerated data and escaped regardless.
  const csrf = escapeHtml(session.csrf);
  const stage = escapeHtml(session.stage);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${csrf}">
  <meta name="recovery-stage" content="${stage}">
  <title>Hospital Account Recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme: light; --ink: #142c3f; --blue: #005e9e; --pale: #eef7fb; --line: #b9cbd6; --danger: #a32424; --success: #176a43; }
    * { box-sizing: border-box; }
    body { margin: 0; background: #f5f8fa; color: var(--ink); font: 17px/1.5 Arial, Helvetica, sans-serif; }
    header { background: #073b5c; color: white; padding: 1.2rem max(1rem, calc((100% - 980px) / 2)); }
    header h1 { font-size: 1.45rem; margin: 0; }
    header p { margin: .2rem 0 0; font-size: .96rem; }
    main { max-width: 980px; margin: 1.75rem auto; padding: 0 1rem; display: grid; grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr); gap: 1.25rem; }
    section, aside { background: white; border: 1px solid var(--line); border-radius: 8px; padding: 1.35rem; box-shadow: 0 1px 2px #1231; }
    h2 { margin-top: 0; font-size: 1.35rem; }
    h3 { font-size: 1.05rem; margin-bottom: .35rem; }
    label { display: block; margin: .9rem 0 .3rem; font-weight: bold; }
    input { width: 100%; padding: .7rem; border: 1px solid #708797; border-radius: 4px; font: inherit; }
    input:focus { outline: 3px solid #87c8ef; outline-offset: 1px; }
    button { margin-top: 1.15rem; background: var(--blue); border: 2px solid var(--blue); border-radius: 4px; color: white; cursor: pointer; font: inherit; font-weight: bold; padding: .65rem 1rem; }
    button:hover, button:focus { background: #004a7b; }
    a { color: #004f87; font-weight: bold; }
    .notice { background: var(--pale); border-left: 5px solid var(--blue); padding: .8rem; }
    .warning { background: #fff5d9; border-left: 5px solid #9b6800; padding: .8rem; }
    .status { min-height: 1.5rem; margin-top: 1rem; font-weight: bold; }
    .error { color: var(--danger); }
    .success { color: var(--success); }
    .steps { color: #456; font-size: .92rem; margin-top: -.5rem; }
    .checkbox-row { display: flex; align-items: start; gap: .55rem; margin-top: 1rem; }
    .checkbox-row input { width: auto; margin-top: .35rem; }
    #logs { background: #10212c; border-radius: 4px; color: #d7f2ff; font: .8rem/1.4 monospace; margin: .5rem 0 0; max-height: 180px; overflow: auto; padding: .65rem; white-space: pre-wrap; }
    footer { max-width: 980px; margin: 0 auto 1.5rem; padding: 0 1rem; color: #456; font-size: .9rem; }
    @media (max-width: 720px) { main { grid-template-columns: 1fr; margin-top: 1rem; } }
  </style>
</head>
<body>
  <header>
    <h1>Hospital account recovery</h1>
    <p>Secure access to accept your updated privacy statement</p>
  </header>
  <main>
    <section id="app" aria-live="polite" aria-busy="false">Loading secure recovery…</section>
    <aside aria-label="Security guidance and test logs">
      <h2>Stay safe</h2>
      <div class="warning">
        <strong>Anti-phishing reminder:</strong> Hospital staff will never ask for your password, reset token, or MFA code by email, text, or telephone. Enter codes only on this HTTPS page.
      </div>
      <h3>Recovery test logs</h3>
      <p>Simulated delivery codes appear here and in the browser console for this evaluation only.</p>
      <div id="logs" role="log" aria-live="polite">No simulated messages yet.</div>
    </aside>
  </main>
  <footer>Use only this hospital page. Recovery always remains within this secure internal service.</footer>

  <script nonce="${nonce}">
    (() => {
      "use strict";
      // Requirement 2: client text is always inserted through textContent, never innerHTML.
      const app = document.getElementById("app");
      const logs = document.getElementById("logs");
      const csrf = document.querySelector('meta[name="csrf-token"]').content;
      let stage = document.querySelector('meta[name="recovery-stage"]').content;
      let statusMessage = "";
      let statusKind = "";

      function element(name, attributes, children) {
        const node = document.createElement(name);
        if (attributes) {
          Object.entries(attributes).forEach(([key, value]) => {
            if (key === "className") node.className = String(value);
            else if (key === "text") node.textContent = String(value);
            else if (key === "checked") node.checked = Boolean(value);
            else node.setAttribute(key, String(value));
          });
        }
        (children || []).forEach((child) => {
          node.append(child.nodeType ? child : document.createTextNode(String(child)));
        });
        return node;
      }

      function mockLog(message) {
        console.log(message);
        if (logs.textContent === "No simulated messages yet.") logs.textContent = "";
        logs.textContent += (logs.textContent ? "\\n" : "") + message;
        logs.scrollTop = logs.scrollHeight;
      }

      function routeForStage() {
        if (stage === "tokenVerified") return "password";
        if (stage === "passwordSet") return "mfa";
        if (stage === "mfaVerified") return "privacy";
        if (stage === "privacyAccepted") return "complete";
        return "recover";
      }

      function setStatus(message, kind) {
        statusMessage = message || "";
        statusKind = kind || "";
      }

      function navigate(route) {
        window.location.hash = route;
      }

      async function api(path, payload) {
        app.setAttribute("aria-busy", "true");
        try {
          const response = await fetch(path, {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrf
            },
            body: JSON.stringify(payload || {})
          });
          const result = await response.json();
          if (!response.ok || !result.ok) throw new Error(result.message || "We could not complete that request.");
          return result;
        } finally {
          app.setAttribute("aria-busy", "false");
        }
      }

      function statusNode() {
        return element("p", { className: "status " + statusKind, text: statusMessage });
      }

      function screenShell(title, description) {
        const holder = document.createDocumentFragment();
        holder.append(
          element("h2", { text: title }),
          element("p", { className: "steps", text: description })
        );
        return holder;
      }

      function recoveryScreen() {
        const content = screenShell("Reset your password", "Step 1 of 5: request a secure recovery token.");
        content.append(element("p", { className: "notice", text: "For privacy, the same confirmation is shown for every request. Do not include medical details in this form." }));
        const form = element("form", { novalidate: "" });
        const label = element("label", { for: "contact", text: "Account contact" });
        const input = element("input", { id: "contact", name: "contact", type: "text", autocomplete: "email", maxlength: "160", required: "", "aria-describedby": "contact-help" });
        form.append(label, input, element("p", { id: "contact-help", text: "Enter the contact value associated with your account. It is not displayed or retained by this demo." }));
        form.append(element("button", { type: "submit", text: "Request recovery token" }));
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          try {
            const result = await api("/api/recovery/request", { contact: input.value });
            if (result.testResetToken) mockLog("Simulated reset token: " + result.testResetToken);
            setStatus(result.message, "success");
            navigate("verify");
          } catch (error) {
            setStatus(error.message, "error");
            render();
          }
        });
        content.append(form, statusNode());
        return content;
      }

      function verificationScreen() {
        const content = screenShell("Verify recovery token", "Step 2 of 5: enter the one-time token from the simulated secure delivery.");
        content.append(element("p", { className: "notice", text: "For this evaluation, request delivery writes a test token to the browser console and the visible logs panel. In normal use, never share tokens with callers." }));
        const form = element("form", { novalidate: "" });
        const label = element("label", { for: "token", text: "Recovery token" });
        const input = element("input", { id: "token", name: "token", type: "text", autocomplete: "one-time-code", maxlength: "128", required: "" });
        form.append(label, input, element("button", { type: "submit", text: "Verify token" }));
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          try {
            const result = await api("/api/recovery/verify-token", { token: input.value });
            stage = result.stage;
            setStatus("", "");
            navigate("password");
          } catch (error) {
            setStatus(error.message, "error");
            render();
          }
        });
        content.append(form, statusNode(), element("p", {}, ["Need a new token? ", element("a", { href: "#recover", text: "Return to recovery request" })]));
        return content;
      }

      function passwordScreen() {
        const content = screenShell("Create a new password", "Step 3 of 5: choose a strong password.");
        content.append(element("p", { className: "notice", text: "Use 12–128 characters with uppercase, lowercase, number, and symbol. Your password is never sent by email or displayed in logs." }));
        const form = element("form", { novalidate: "" });
        const label = element("label", { for: "password", text: "New password" });
        const input = element("input", { id: "password", name: "password", type: "password", autocomplete: "new-password", maxlength: "128", required: "" });
        form.append(label, input, element("button", { type: "submit", text: "Save new password" }));
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          try {
            const result = await api("/api/recovery/password", { password: input.value });
            input.value = "";
            stage = result.stage;
            if (result.testMfaCode) mockLog("Simulated MFA code: " + result.testMfaCode);
            setStatus("", "");
            navigate("mfa");
          } catch (error) {
            input.value = "";
            setStatus(error.message, "error");
            render();
          }
        });
        content.append(form, statusNode());
        return content;
      }

      function mfaScreen() {
        const content = screenShell("Confirm your security code", "Step 4 of 5: multi-factor authentication is required.");
        content.append(element("p", { className: "notice", text: "Enter the simulated MFA code from the browser console or test logs. Do not give this code to staff or callers." }));
        const form = element("form", { novalidate: "" });
        const label = element("label", { for: "mfa", text: "Six-digit security code" });
        const input = element("input", { id: "mfa", name: "mfa", type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", required: "" });
        form.append(label, input, element("button", { type: "submit", text: "Verify security code" }));
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          try {
            const result = await api("/api/recovery/mfa", { code: input.value });
            stage = result.stage;
            setStatus("", "");
            navigate("privacy");
          } catch (error) {
            setStatus(error.message, "error");
            render();
          }
        });
        content.append(form, statusNode());
        return content;
      }

      function privacyScreen() {
        const content = screenShell("Updated privacy statement", "Step 5 of 5: accept the statement in this authenticated recovery session.");
        content.append(element("p", { className: "notice", text: "Your account recovery is complete. Hospital authorities can proceed with appointment booking only after you accept this statement." }));
        content.append(element("p", { text: "I understand that my healthcare account information is private and that access is protected by the hospital's updated privacy conditions." }));
        const form = element("form", {});
        const check = element("input", { id: "accept", type: "checkbox", required: "" });
        const row = element("label", { className: "checkbox-row", for: "accept" }, [check, "I accept the updated privacy statement."]);
        form.append(row, element("button", { type: "submit", text: "Accept privacy statement" }));
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (!check.checked) {
            setStatus("Please confirm acceptance before continuing.", "error");
            render();
            return;
          }
          try {
            // Requirement task: send an explicit boolean derived from checkbox state.
            const result = await api("/api/recovery/privacy-accept", { accepted: check.checked });
            stage = result.stage;
            setStatus("", "");
            navigate("complete");
          } catch (error) {
            setStatus(error.message, "error");
            render();
          }
        });
        content.append(form, statusNode());
        return content;
      }

      function completionScreen() {
        const content = screenShell("Privacy statement accepted", "Recovery and verification are complete.");
        content.append(element("p", { className: "notice", text: "Your acceptance was recorded only for this authenticated secure session. You may now safely return to the hospital appointment process." }));
        content.append(element("p", { text: "For your security, close this page when you are finished and never share passwords or security codes." }));
        return content;
      }

      function unavailableScreen() {
        const route = routeForStage();
        const content = screenShell("Continue secure recovery", "This step requires completion of the previous security check.");
        content.append(element("p", { className: "notice", text: "No account details were revealed. Continue using the secure internal recovery route." }));
        content.append(element("p", {}, [element("a", { href: "#" + route, text: "Continue recovery" })]));
        return content;
      }

      function render() {
        const requested = (window.location.hash || "#"+routeForStage()).slice(1);
        const allowed = {
          request: ["recover", "verify"],
          tokenVerified: ["password"],
          passwordSet: ["mfa"],
          mfaVerified: ["privacy"],
          privacyAccepted: ["complete"]
        };
        let screen;
        if (!allowed[stage] || !allowed[stage].includes(requested)) {
          screen = unavailableScreen();
        } else if (requested === "recover") {
          screen = recoveryScreen();
        } else if (requested === "verify") {
          screen = verificationScreen();
        } else if (requested === "password") {
          screen = passwordScreen();
        } else if (requested === "mfa") {
          screen = mfaScreen();
        } else if (requested === "privacy") {
          screen = privacyScreen();
        } else {
          screen = completionScreen();
        }
        app.replaceChildren(screen);
      }

      window.addEventListener("hashchange", () => {
        setStatus("", "");
        render();
      });
      if (!window.location.hash) window.location.hash = routeForStage();
      render();
    })();
  </script>
</body>
</html>`;
}

async function handlePost(request: Request, path: string): Promise<Response> {
  const check = requireCsrf(request);
  if (check.error) return check.error;
  const session = check.session!;
  const body = await requestJson(request);

  if (!body) return jsonResponse({ ok: false, message: "We could not process that request." }, 400);

  if (path === "/api/recovery/request") {
    // Requirement task: global IP/action limit survives session recreation.
    if (ipThrottled(request, "recoveryTokenIssuance", 3) || throttled(session, "recoveryRequest", 3)) {
      return jsonResponse({ ok: false, message: "Please wait before making another recovery request." }, 429);
    }

    const token = randomOpaqueValue(32);
    session.recovery = {
      tokenDigest: digest(token),
      expiresAt: Date.now() + RESET_TOKEN_TTL_MS,
      used: false,
    };
    session.stage = "request";

    // Requirement 5: no contact value is logged, stored, reflected, or sent anywhere.
    return jsonResponse({
      ok: true,
      message: "If the contact can be used for recovery, a secure recovery message has been prepared. Check the evaluation logs for the simulated token.",
      testResetToken: token,
    });
  }

  if (path === "/api/recovery/verify-token") {
    // Requirement 4/task: both session and trusted-IP throttles prevent token guessing.
    if (ipThrottled(request, "resetTokenVerification", 5) || throttled(session, "tokenVerification", 5)) {
      return jsonResponse({ ok: false, message: "Too many verification attempts. Please wait before trying again." }, 429);
    }

    const token = typeof body.token === "string" ? body.token : "";
    const record = session.recovery;
    const valid =
      session.stage === "request" &&
      !!record &&
      !record.used &&
      record.expiresAt > Date.now() &&
      token.length > 0 &&
      safeEqual(digest(token), record.tokenDigest);

    if (!valid) {
      return jsonResponse({ ok: false, message: "That recovery token cannot be verified. Request a new token or try again." }, 400);
    }

    record.used = true;
    session.stage = "tokenVerified";
    return jsonResponse({ ok: true, stage: session.stage });
  }

  if (path === "/api/recovery/password") {
    // Requirement 4/task: password submissions are limited by trusted IP and session.
    if (ipThrottled(request, "passwordChangeSubmission", 5) || throttled(session, "passwordChange", 5)) {
      return jsonResponse({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }
    if (session.stage !== "tokenVerified") {
      return jsonResponse({ ok: false, message: "This secure recovery step is not available." }, 403);
    }

    const password = typeof body.password === "string" ? body.password : "";
    const policyError = passwordPolicyError(password);
    if (policyError) return jsonResponse({ ok: false, message: `Password requirements: ${policyError}` }, 400);

    try {
      session.passwordHash = await Bun.password.hash(password, {
        algorithm: "bcrypt",
        cost: 12,
      });
    } catch {
      return jsonResponse({ ok: false, message: "We could not save the new password. Please try again." }, 500);
    }

    // Requirement 4: deterministic evaluation-only MFA challenge, delivered to browser log by client.
    session.mfaCode = "482913";
    session.stage = "passwordSet";
    return jsonResponse({ ok: true, stage: session.stage, testMfaCode: session.mfaCode });
  }

  if (path === "/api/recovery/mfa") {
    // Requirement task: MFA verification has its own trusted-IP/action bucket.
    if (ipThrottled(request, "mfaVerification", 5) || throttled(session, "mfaVerification", 5)) {
      return jsonResponse({ ok: false, message: "Too many verification attempts. Please wait before trying again." }, 429);
    }
    if (session.stage !== "passwordSet" || !session.mfaCode) {
      return jsonResponse({ ok: false, message: "This security check is not available." }, 403);
    }

    const code = typeof body.code === "string" ? body.code : "";
    if (!safeEqual(code, session.mfaCode)) {
      return jsonResponse({ ok: false, message: "The security code could not be verified." }, 400);
    }

    session.mfaCode = undefined;
    session.stage = "mfaVerified";
    return jsonResponse({ ok: true, stage: session.stage });
  }

  if (path === "/api/recovery/privacy-accept") {
    // Requirement task: explicit JSON boolean is mandatory; failure leaves stage unchanged.
    if (body.accepted !== true) {
      return jsonResponse({ ok: false, message: "Please confirm acceptance before continuing." }, 400);
    }

    // Requirement 1: no query/body identifier can choose another privacy record; this session alone is updated.
    if (session.stage !== "mfaVerified") {
      return jsonResponse({ ok: false, message: "Complete secure verification before accepting this statement." }, 403);
    }

    session.privacyAccepted = true;
    session.stage = "privacyAccepted";
    return jsonResponse({ ok: true, stage: session.stage });
  }

  return jsonResponse({ ok: false, message: "Not found." }, 404);
}

server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  // Requirement 3: this listener is TLS-only. Plain HTTP sent to this port is rejected by TLS negotiation.
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);

      // Defense in depth: only HTTPS-origin requests are served.
      if (url.protocol !== "https:") {
        const headers = securityHeaders(randomOpaqueValue(16));
        headers.set("Content-Type", "text/plain; charset=utf-8");
        return new Response("HTTPS is required.", { status: 400, headers });
      }

      if (request.method === "GET" && url.pathname === "/") {
        const { session, isNew } = getSession(request, true);
        const nonce = randomOpaqueValue(18);
        const headers = securityHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
        return new Response(page(session!, nonce), { status: 200, headers });
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/recovery/")) {
        return await handlePost(request, url.pathname);
      }

      return jsonResponse({ ok: false, message: "Not found." }, 404);
    } catch {
      // Requirement 3: no stack traces/debug information are exposed to clients.
      return jsonResponse({ ok: false, message: "The secure service could not process this request." }, 500);
    }
  },
});

console.log(`Secure Hospital Recovery service listening at https://localhost:${server.port}`);
