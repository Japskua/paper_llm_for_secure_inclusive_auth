
const PORT = 3000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const TOKEN_TTL_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;

type Limit = { failures: number; lockedUntil: number; windowStarted: number };
type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  limits: Record<string, Limit>;
  verifiedTokenHash?: string;
  mfaVerified: boolean;
  passwordChanged: boolean;
  privacyAccepted: boolean;
};
type RecoveryToken = {
  hash: string;
  sessionId: string;
  accountBinding: string;
  expiresAt: number;
  used: boolean;
};
type Account = { passwordHash: string };

const sessions = new Map<string, Session>();
const recoveryTokens = new Map<string, RecoveryToken>();
const account: Account = { passwordHash: "" };

/* Requirements 1, 3, 4: cryptographically random session, CSRF, and reset values. */
function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  let binary = "";
  for (const value of values) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function sha256(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function cleanExpiredState(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (session.expiresAt < now) sessions.delete(id);
  }
  for (const [hash, token] of recoveryTokens) {
    if (token.expiresAt < now && token.used) recoveryTokens.delete(hash);
  }
}

function parseCookies(request: Request): Record<string, string> {
  const source = request.headers.get("cookie") || "";
  const cookies: Record<string, string> = {};
  for (const item of source.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) cookies[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return cookies;
}

function getSession(request: Request): Session | undefined {
  cleanExpiredState();
  const id = parseCookies(request).recovery_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expiresAt < Date.now()) return undefined;
  return session;
}

function createSession(): Session {
  const session: Session = {
    id: randomValue(32),
    csrf: randomValue(32),
    expiresAt: Date.now() + SESSION_TTL_MS,
    limits: {},
    mfaVerified: false,
    passwordChanged: false,
    privacyAccepted: false,
  };
  sessions.set(session.id, session);
  return session;
}

/* Requirements 1 and 4: state-changing requests require this session-bound CSRF value. */
function csrfValid(request: Request, session: Session | undefined): boolean {
  if (!session) return false;
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length > 20 && supplied === session.csrf;
}

function limitStatus(session: Session, category: string): { allowed: boolean; retrySeconds?: number } {
  const limit = session.limits[category];
  if (!limit) return { allowed: true };
  const now = Date.now();
  if (limit.lockedUntil > now) {
    return { allowed: false, retrySeconds: Math.ceil((limit.lockedUntil - now) / 1000) };
  }
  if (now - limit.windowStarted > LOCK_MS) {
    delete session.limits[category];
  }
  return { allowed: true };
}

function recordFailure(session: Session, category: string): void {
  const now = Date.now();
  let limit = session.limits[category];
  if (!limit || now - limit.windowStarted > LOCK_MS) {
    limit = { failures: 0, lockedUntil: 0, windowStarted: now };
    session.limits[category] = limit;
  }
  limit.failures++;
  if (limit.failures >= 5) limit.lockedUntil = now + LOCK_MS;
}

function clearFailures(session: Session, category: string): void {
  delete session.limits[category];
}

function securityHeaders(nonce = ""): Headers {
  const headers = new Headers();
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  headers.set("Pragma", "no-cache");
  headers.set(
    "Content-Security-Policy",
    nonce
      ? "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
      : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
  return headers;
}

function json(body: Record<string, unknown>, status = 200): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function safeError(status: number, message = "We could not complete that request. Please try again."): Response {
  return json({ ok: false, message }, status);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 20_000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validShortString(value: unknown, maximum = 300): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function passwordPolicy(password: string): string | null {
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) return "Include upper- and lower-case letters.";
  if (!/[0-9]/.test(password)) return "Include at least one number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include at least one symbol.";
  return null;
}

/* Requirements 2 and single-file constraint: fixed markup only; no user input is templated into HTML. */
const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="__NONCE__">
:root { color-scheme: light; --blue:#075a9b; --ink:#142334; --soft:#edf5fa; --line:#b9cad7; --danger:#a51d2d; }
* { box-sizing:border-box; }
body { margin:0; background:#f5f8fa; color:var(--ink); font:17px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
header { background:#073d68; color:white; padding:1.15rem max(1.2rem,calc((100% - 860px)/2)); }
header h1 { margin:0; font-size:1.45rem; } header p { margin:.2rem 0 0; }
main { width:min(860px,100%); margin:2rem auto; padding:0 1.2rem 2rem; }
.card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.5rem; box-shadow:0 2px 8px #1232; }
.view[hidden] { display:none; }
h2 { margin-top:0; } label { display:block; font-weight:700; margin-top:1rem; }
input { display:block; width:100%; max-width:560px; padding:.72rem; font:inherit; border:1px solid #62798a; border-radius:5px; }
button { margin-top:1.25rem; padding:.7rem 1rem; border:0; border-radius:5px; background:var(--blue); color:white; cursor:pointer; font:inherit; font-weight:700; }
button.secondary { background:#e4edf3; color:#173047; margin-left:.4rem; } button:hover { filter:brightness(.93); }
.notice { margin:1rem 0; padding:.85rem; border-left:4px solid var(--blue); background:var(--soft); }
.status { min-height:1.6rem; font-weight:600; } .status.error { color:var(--danger); } .status.good { color:#176b36; }
.small { font-size:.92rem; } .guidance { margin-top:1.4rem; padding:1rem; background:#fff8df; border:1px solid #e6c766; border-radius:6px; }
nav { margin:.8rem 0 1.2rem; } nav button { margin:.15rem; font-size:.9rem; }
#logs { margin-top:1.5rem; background:#10202e; color:#d8edfa; border-radius:8px; padding:1rem; }
#logs h2 { font-size:1rem; } #log-output { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; max-height:190px; overflow:auto; font:13px/1.45 ui-monospace,SFMono-Regular,monospace; }
footer { text-align:center; color:#526675; font-size:.9rem; padding:1rem; }
</style>
</head>
<body>
<header><h1>Hospital personal healthcare account</h1><p>Secure account recovery</p></header>
<main>
<nav aria-label="Recovery steps">
<button class="secondary" type="button" data-view="request">1. Request</button>
<button class="secondary" type="button" data-view="token">2. Token</button>
<button class="secondary" type="button" data-view="mfa">3. Verify</button>
</nav>

<section class="card view" id="view-request" aria-labelledby="request-title">
<h2 id="request-title">Reset your password</h2>
<p>Enter the email address or mobile number associated with your account. For privacy, the response is the same whether or not an account is found.</p>
<form id="request-form">
<label for="contact">Email address or mobile number</label>
<input id="contact" name="contact" autocomplete="username" maxlength="300" required>
<button type="submit">Send recovery instructions</button>
</form>
<p id="request-status" class="status" role="status" aria-live="polite"></p>
<p class="small">Already received a code? <button class="secondary" type="button" data-view="token">Enter it manually</button></p>
</section>

<section class="card view" id="view-token" hidden aria-labelledby="token-title">
<h2 id="token-title">Enter recovery token</h2>
<p>Use the token from the recovery instructions. A recovery link is also checked automatically when opened in this portal.</p>
<form id="token-form">
<label for="token">Recovery token</label>
<input id="token" name="token" autocomplete="one-time-code" maxlength="200" required>
<button type="submit">Verify token</button>
</form>
<p id="token-status" class="status" role="status" aria-live="polite"></p>
</section>

<section class="card view" id="view-mfa" hidden aria-labelledby="mfa-title">
<h2 id="mfa-title">Additional verification</h2>
<p>For this local demonstration, a test verification code is delivered to the browser console and the Logs panel.</p>
<form id="mfa-form">
<label for="mfa">Verification code</label>
<input id="mfa" name="mfa" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required>
<button type="submit">Verify code</button>
</form>
<p id="mfa-status" class="status" role="status" aria-live="polite"></p>
</section>

<section class="card view" id="view-password" hidden aria-labelledby="password-title">
<h2 id="password-title">Choose a new password</h2>
<p>Use 12 or more characters with upper- and lower-case letters, a number, and a symbol.</p>
<form id="password-form">
<label for="password">New password</label>
<input id="password" name="password" type="password" autocomplete="new-password" maxlength="128" required>
<label for="confirm-password">Confirm new password</label>
<input id="confirm-password" name="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required>
<button type="submit">Save new password</button>
</form>
<p id="password-status" class="status" role="status" aria-live="polite"></p>
</section>

<section class="card view" id="view-privacy" hidden aria-labelledby="privacy-title">
<h2 id="privacy-title">Updated privacy conditions</h2>
<p>Please confirm that you have reviewed the updated privacy conditions. This enables hospital authorities to proceed with appointment booking.</p>
<div class="notice"><strong>Privacy notice:</strong> Your health information is handled only within the hospital service. This local demo does not contact outside services.</div>
<form id="privacy-form">
<label><input id="privacy-check" type="checkbox" required> I have reviewed and accept the updated privacy conditions.</label>
<button type="submit">Accept conditions</button>
</form>
<p id="privacy-status" class="status" role="status" aria-live="polite"></p>
</section>

<section class="card view" id="view-confirmation" hidden aria-labelledby="confirmation-title">
<h2 id="confirmation-title">Recovery complete</h2>
<p>Your password has been updated and the privacy conditions have been accepted. Hospital authorities can now continue the appointment process.</p>
<p class="notice">For your security, sign in only through the hospital portal.</p>
<button type="button" data-view="request">Return to recovery start</button>
</section>

<aside class="guidance" aria-labelledby="guidance-title">
<h2 id="guidance-title">Stay safe</h2>
<p>Never share your password, recovery token, or verification code by email, text message, or with a caller. The hospital portal does not request credentials through external links. Type the local portal address yourself before signing in.</p>
</aside>

<section id="logs" aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><pre id="log-output">Local recovery simulation ready.</pre></section>
</main>
<footer>Local HTTPS recovery demonstration — no external network services are used.</footer>

<script nonce="__NONCE__">
"use strict";
const CSRF = "__CSRF__";
const allowedViews = new Set(["request","token","mfa","password","privacy","confirmation"]);
const logOutput = document.getElementById("log-output");
function localLog(message) {
  console.log(message);
  logOutput.textContent += "\n" + message;
  logOutput.scrollTop = logOutput.scrollHeight;
}
function status(id, message, good) {
  const node = document.getElementById(id);
  node.textContent = message || "";
  node.className = "status" + (message ? (good ? " good" : " error") : "");
}
function show(view) {
  const safe = allowedViews.has(view) ? view : "request";
  document.querySelectorAll(".view").forEach(function(node) { node.hidden = node.id !== "view-" + safe; });
  history.replaceState(null, "", location.pathname + (location.search ? location.search : "") + "#" + safe);
  document.getElementById("view-" + safe).querySelector("h2").focus && document.getElementById("view-" + safe).querySelector("h2").focus();
}
document.querySelectorAll("[data-view]").forEach(function(button) {
  button.addEventListener("click", function() { show(button.dataset.view); });
});
async function post(path, payload) {
  try {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    return result;
  } catch (_) {
    return { ok:false, message:"Unable to reach the local secure service. Please try again." };
  }
}
document.getElementById("request-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  status("request-status", "Sending recovery instructions…", true);
  const contact = document.getElementById("contact").value;
  const result = await post("/api/recovery-request", { contact:contact });
  status("request-status", result.message, !!result.ok);
  if (result.ok) {
    localLog("[Mock delivery] Recovery instructions prepared locally. Test token: " + result.testToken);
    localLog("[Mock delivery] Local verification link: " + result.testLink);
    document.getElementById("token").value = "";
    show("token");
  }
});
async function verifyToken(value) {
  const result = await post("/api/verify-token", { token:value });
  status("token-status", result.message, !!result.ok);
  if (result.ok) {
    localLog("[Mock delivery] Deterministic MFA test code: " + result.mfaTestCode);
    show("mfa");
  }
}
document.getElementById("token-form").addEventListener("submit", function(event) {
  event.preventDefault();
  verifyToken(document.getElementById("token").value);
});
document.getElementById("mfa-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const result = await post("/api/verify-mfa", { code:document.getElementById("mfa").value });
  status("mfa-status", result.message, !!result.ok);
  if (result.ok) show("password");
});
document.getElementById("password-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const password = document.getElementById("password").value;
  const confirmation = document.getElementById("confirm-password").value;
  if (password !== confirmation) { status("password-status", "The passwords do not match.", false); return; }
  const result = await post("/api/set-password", { password:password });
  document.getElementById("password").value = "";
  document.getElementById("confirm-password").value = "";
  status("password-status", result.message, !!result.ok);
  if (result.ok) show("privacy");
});
document.getElementById("privacy-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  if (!document.getElementById("privacy-check").checked) { status("privacy-status", "Please confirm acceptance before continuing.", false); return; }
  const result = await post("/api/accept-privacy", { accepted:true });
  status("privacy-status", result.message, !!result.ok);
  if (result.ok) show("confirmation");
});
const urlToken = new URLSearchParams(location.search).get("token");
const requestedView = location.hash.slice(1);
if (urlToken && /^[A-Za-z0-9_-]{20,200}$/.test(urlToken)) {
  history.replaceState(null, "", location.pathname + "#token");
  document.getElementById("token").value = urlToken;
  show("token");
  localLog("[Mock delivery] Recovery link received locally; checking its token.");
  verifyToken(urlToken);
} else {
  show(allowedViews.has(requestedView) ? requestedView : "request");
}
</script>
</body>
</html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const session = getSession(request);
  if (request.method !== "POST") return safeError(405, "That action is not available.");
  if (!csrfValid(request, session)) return safeError(403, "Your secure session could not be verified. Refresh the page and try again.");
  const body = await requestBody(request);
  if (!body || !session) return safeError(400);

  if (pathname === "/api/recovery-request") {
    const limited = limitStatus(session, "recovery");
    if (!limited.allowed) return json({ ok: false, message: "Please wait " + limited.retrySeconds + " seconds before trying again." }, 429);
    const contact = body.contact;
    if (!validShortString(contact)) {
      recordFailure(session, "recovery");
      return json({ ok: true, message: "If an eligible account exists, recovery instructions have been sent." });
    }
    const requests = session.limits.recovery;
    if (requests && requests.failures >= 3) {
      requests.lockedUntil = Date.now() + LOCK_MS;
      return json({ ok: false, message: "Please wait before requesting another recovery message." }, 429);
    }
    if (!session.limits.recovery) session.limits.recovery = { failures: 0, lockedUntil: 0, windowStarted: Date.now() };
    session.limits.recovery.failures++;

    const token = randomValue(32);
    const hash = await sha256(token);
    recoveryTokens.set(hash, {
      hash,
      sessionId: session.id,
      accountBinding: "local-recovery-account",
      expiresAt: Date.now() + TOKEN_TTL_MS,
      used: false,
    });
    return json({
      ok: true,
      message: "If an eligible account exists, recovery instructions have been sent.",
      testToken: token,
      testLink: "/?token=" + encodeURIComponent(token),
    });
  }

  if (pathname === "/api/verify-token") {
    const limited = limitStatus(session, "token");
    if (!limited.allowed) return json({ ok: false, message: "Too many attempts. Try again in " + limited.retrySeconds + " seconds." }, 429);
    const supplied = body.token;
    if (!validShortString(supplied, 200) || !/^[A-Za-z0-9_-]+$/.test(supplied)) {
      recordFailure(session, "token");
      return json({ ok: false, message: "This recovery token is invalid, expired, or has already been used." }, 400);
    }
    const hash = await sha256(supplied);
    const token = recoveryTokens.get(hash);
    if (!token || token.sessionId !== session.id || token.accountBinding !== "local-recovery-account" || token.used || token.expiresAt < Date.now()) {
      recordFailure(session, "token");
      return json({ ok: false, message: "This recovery token is invalid, expired, or has already been used." }, 400);
    }
    token.used = true;
    session.verifiedTokenHash = hash;
    clearFailures(session, "token");
    return json({ ok: true, message: "Recovery token verified. Enter the verification code.", mfaTestCode: "482913" });
  }

  if (pathname === "/api/verify-mfa") {
    const limited = limitStatus(session, "mfa");
    if (!limited.allowed) return json({ ok: false, message: "Too many attempts. Try again in " + limited.retrySeconds + " seconds." }, 429);
    if (!session.verifiedTokenHash || body.code !== "482913") {
      recordFailure(session, "mfa");
      return json({ ok: false, message: "The verification code could not be confirmed." }, 400);
    }
    session.mfaVerified = true;
    clearFailures(session, "mfa");
    return json({ ok: true, message: "Verification complete. You may set a new password." });
  }

  if (pathname === "/api/set-password") {
    const limited = limitStatus(session, "password");
    if (!limited.allowed) return json({ ok: false, message: "Too many attempts. Try again in " + limited.retrySeconds + " seconds." }, 429);
    if (!session.mfaVerified || !session.verifiedTokenHash) {
      recordFailure(session, "password");
      return json({ ok: false, message: "Your recovery verification is required before changing a password." }, 403);
    }
    const password = body.password;
    if (!validShortString(password, 128)) return json({ ok: false, message: "Choose a password meeting the stated requirements." }, 400);
    const policyError = passwordPolicy(password);
    if (policyError) return json({ ok: false, message: policyError }, 400);
    /* Requirement 4: Bun bcrypt hash only; plaintext is neither logged nor returned. */
    account.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    session.passwordChanged = true;
    clearFailures(session, "password");
    return json({ ok: true, message: "Your new password has been saved securely." });
  }

  if (pathname === "/api/accept-privacy") {
    if (!session.mfaVerified || !session.passwordChanged || body.accepted !== true) {
      return json({ ok: false, message: "Complete secure recovery before accepting privacy conditions." }, 403);
    }
    session.privacyAccepted = true;
    return json({ ok: true, message: "Privacy conditions accepted." });
  }

  return safeError(404, "That service is not available.");
}

/* Requirements 3 and single-file/no-network: HTTPS Bun server with local mkcert files only. */
Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        let isNew = false;
        if (!session) {
          session = createSession();
          isNew = true;
        }
        const nonce = randomValue(18);
        const html = PAGE.replaceAll("__NONCE__", nonce).replaceAll("__CSRF__", session.csrf);
        const headers = securityHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        if (isNew) {
          headers.append(
            "Set-Cookie",
            "recovery_session=" + session.id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(SESSION_TTL_MS / 1000),
          );
        }
        return new Response(html, { status: 200, headers });
      }
      return safeError(404, "The requested page is not available.");
    } catch {
      return safeError(500, "The secure service is temporarily unavailable.");
    }
  },
});
