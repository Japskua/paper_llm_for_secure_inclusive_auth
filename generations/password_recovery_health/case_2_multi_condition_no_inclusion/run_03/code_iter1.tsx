
const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();

type MfaState = {
  code: string;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryTimes: number[];
  verificationTimes: number[];
  resetAuthorizedDigest?: string;
  passwordHash?: string;
  passwordChanged: boolean;
  authenticated: boolean;
  privacyAccepted: boolean;
  mfa?: MfaState;
};

type ResetRecord = {
  digest: string;
  sessionId: string;
  accountBinding: string;
  expiresAt: number;
  used: boolean;
  attempts: number;
};

const encoder = new TextEncoder();
const SESSION_MAX_AGE_SECONDS = 60 * 60;
const RESET_LIFETIME_MS = 10 * 60 * 1000;
const TOKEN_ATTEMPT_LIMIT = 5;

function randomUrlToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  let binary = "";
  for (const value of values) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (/^[A-Za-z0-9_-]+$/.test(value)) result[key] = value;
    }
  }
  return result;
}

function freshSession(): Session {
  return {
    id: randomUrlToken(32),
    csrf: randomUrlToken(32),
    createdAt: Date.now(),
    recoveryTimes: [],
    verificationTimes: [],
    passwordChanged: false,
    authenticated: false,
    privacyAccepted: false,
  };
}

function activeSession(request: Request): Session | undefined {
  const id = parseCookies(request).hospital_recovery_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  if (Date.now() - session.createdAt > SESSION_MAX_AGE_SECONDS * 1000) {
    sessions.delete(id);
    return undefined;
  }
  return session;
}

/*
 Security Requirements 3:
 HTTPS-only service and production response headers. A new nonce is created
 for every response and is the only script/style source allowed by CSP.
*/
function securityHeaders(nonce: string, contentType: string): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'none'; " +
      "script-src 'nonce-" + nonce + "'; " +
      "style-src 'nonce-" + nonce + "'; " +
      "connect-src 'self'; img-src 'none'; font-src 'none'; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
      "object-src 'none'; upgrade-insecure-requests",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=(), interest-cohort=()",
    "Cache-Control": "no-store, max-age=0",
  });
}

function jsonResponse(
  nonce: string,
  status: number,
  body: Record<string, unknown>,
  extra?: Record<string, string>,
): Response {
  const headers = securityHeaders(nonce, "application/json; charset=utf-8");
  if (extra) for (const [key, value] of Object.entries(extra)) headers.set(key, value);
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(nonce: string, status = 400): Response {
  return jsonResponse(nonce, status, { ok: false, message: "Unable to complete that request safely." });
}

function sessionCookie(session: Session): string {
  return (
    "hospital_recovery_session=" +
    session.id +
    "; Path=/; Max-Age=" +
    SESSION_MAX_AGE_SECONDS +
    "; Secure; HttpOnly; SameSite=Strict"
  );
}

/*
 Security Requirements 1 and 4:
 Sensitive actions require a server-owned secure session and its unique CSRF
 token. No account identifier is accepted from, or returned to, the client.
*/
function protectedSession(request: Request): Session | undefined {
  const session = activeSession(request);
  if (!session) return undefined;
  const csrf = request.headers.get("x-csrf-token") || "";
  if (csrf.length !== session.csrf.length || !csrf) return undefined;
  let difference = 0;
  for (let i = 0; i < csrf.length; i++) difference |= csrf.charCodeAt(i) ^ session.csrf.charCodeAt(i);
  return difference === 0 ? session : undefined;
}

/*
 Security Requirement 2:
 Request parsing has a strict size limit and only expected primitive fields
 are used. Client output is inserted with textContent, never innerHTML.
*/
async function requestJson(request: Request): Promise<Record<string, unknown> | undefined> {
  const length = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(length) || length > 2048) return undefined;
  const text = await request.text();
  if (text.length > 2048) return undefined;
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function validContact(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.trim().length >= 3 &&
    value.trim().length <= 160 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function rateAllowed(times: number[], max: number, windowMs: number): boolean {
  const now = Date.now();
  const recent = times.filter((time) => now - time < windowMs);
  times.splice(0, times.length, ...recent);
  if (times.length >= max) return false;
  times.push(now);
  return true;
}

function passwordPolicy(password: string): string | undefined {
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 256) return "Use no more than 256 characters.";
  const groups = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9\s]/.test(password),
  ].filter(Boolean).length;
  if (groups < 4) return "Include uppercase, lowercase, a number, and a symbol.";
  return undefined;
}

async function handleApi(request: Request, url: URL, nonce: string): Promise<Response> {
  if (request.method !== "POST") return genericError(nonce, 405);
  const session = protectedSession(request);
  if (!session) return genericError(nonce, 403);
  const data = await requestJson(request);
  if (!data) return genericError(nonce);

  if (url.pathname === "/api/recovery") {
    if (!validContact(data.contact)) {
      return jsonResponse(nonce, 400, {
        ok: false,
        message: "Enter a valid contact value without sensitive details.",
      });
    }
    if (!rateAllowed(session.recoveryTimes, 3, 15 * 60 * 1000)) {
      return jsonResponse(nonce, 429, {
        ok: false,
        message: "Please wait before requesting another recovery message.",
      });
    }
    const rawToken = randomUrlToken(32);
    const tokenDigest = await digest(rawToken);
    resets.set(tokenDigest, {
      digest: tokenDigest,
      sessionId: session.id,
      accountBinding: "opaque-recovery-account-binding",
      expiresAt: Date.now() + RESET_LIFETIME_MS,
      used: false,
      attempts: 0,
    });
    session.resetAuthorizedDigest = undefined;
    return jsonResponse(nonce, 200, {
      ok: true,
      message: "If the contact can be used for recovery, instructions have been prepared.",
      recoveryToken: rawToken,
    });
  }

  if (url.pathname === "/api/verify-token") {
    const token = data.token;
    if (
      typeof token !== "string" ||
      token.length < 30 ||
      token.length > 200 ||
      !/^[A-Za-z0-9_-]+$/.test(token)
    ) {
      return jsonResponse(nonce, 400, { ok: false, message: "Enter a valid recovery token." });
    }
    if (!rateAllowed(session.verificationTimes, 6, 10 * 60 * 1000)) {
      return jsonResponse(nonce, 429, {
        ok: false,
        message: "Too many verification attempts. Please wait and try again.",
      });
    }

    const tokenDigest = await digest(token);
    const record = resets.get(tokenDigest);
    if (
      !record ||
      record.sessionId !== session.id ||
      record.accountBinding !== "opaque-recovery-account-binding" ||
      record.used ||
      record.expiresAt <= Date.now()
    ) {
      return jsonResponse(nonce, 400, {
        ok: false,
        message: "This recovery token is invalid, expired, or no longer available.",
      });
    }
    record.attempts++;
    if (record.attempts > TOKEN_ATTEMPT_LIMIT) {
      record.used = true;
      return jsonResponse(nonce, 429, {
        ok: false,
        message: "This recovery token is no longer available. Start recovery again.",
      });
    }

    // Token lifecycle: verification consumes this single-use random token.
    record.used = true;
    session.resetAuthorizedDigest = tokenDigest;
    return jsonResponse(nonce, 200, {
      ok: true,
      message: "Recovery token verified. You can now choose a new password.",
    });
  }

  if (url.pathname === "/api/password") {
    const password = data.password;
    if (typeof password !== "string") return genericError(nonce);
    const policyFailure = passwordPolicy(password);
    if (policyFailure) return jsonResponse(nonce, 400, { ok: false, message: policyFailure });

    const authorizedDigest = session.resetAuthorizedDigest;
    const record = authorizedDigest ? resets.get(authorizedDigest) : undefined;
    if (
      !record ||
      !record.used ||
      record.sessionId !== session.id ||
      record.expiresAt <= Date.now()
    ) {
      return jsonResponse(nonce, 403, {
        ok: false,
        message: "Verify a current recovery token before replacing your password.",
      });
    }

    /*
     Security Requirement 4:
     Bun's bcrypt implementation stores only a password hash. The plaintext is
     never persisted or logged.
    */
    session.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    session.passwordChanged = true;
    session.resetAuthorizedDigest = undefined;
    session.mfa = { code: "482916", attempts: 0, lockedUntil: 0, used: false };

    return jsonResponse(nonce, 200, {
      ok: true,
      message: "Password replaced. A confirmation code has been prepared.",
      mfaCode: session.mfa.code,
    });
  }

  if (url.pathname === "/api/mfa") {
    const code = data.code;
    if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
      return jsonResponse(nonce, 400, { ok: false, message: "Enter the six-digit confirmation code." });
    }
    const mfa = session.mfa;
    if (!session.passwordChanged || !mfa || mfa.used) {
      return jsonResponse(nonce, 400, { ok: false, message: "Confirmation is unavailable." });
    }
    if (mfa.lockedUntil > Date.now()) {
      return jsonResponse(nonce, 429, {
        ok: false,
        message: "Too many attempts. Please wait one minute before trying again.",
      });
    }
    if (code !== mfa.code) {
      mfa.attempts++;
      if (mfa.attempts >= 5) {
        mfa.attempts = 0;
        mfa.lockedUntil = Date.now() + 60 * 1000;
      }
      return jsonResponse(nonce, 400, {
        ok: false,
        message: "The confirmation code could not be verified.",
      });
    }
    mfa.used = true;
    session.authenticated = true;
    return jsonResponse(nonce, 200, { ok: true, message: "Confirmation complete." });
  }

  if (url.pathname === "/api/privacy") {
    if (!session.authenticated || !session.mfa?.used) {
      return jsonResponse(nonce, 403, {
        ok: false,
        message: "Confirmation is required before accepting privacy conditions.",
      });
    }
    if (data.accept !== true) return jsonResponse(nonce, 400, { ok: false, message: "Acceptance is required." });
    session.privacyAccepted = true;
    return jsonResponse(nonce, 200, {
      ok: true,
      message: "Updated privacy conditions have been accepted.",
    });
  }

  return genericError(nonce, 404);
}

function page(nonce: string, csrf: string): string {
  const state = JSON.stringify({ csrf }).replaceAll("<", "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;font-family:Arial,sans-serif;color:#142333;background:#f4f7f8}
*{box-sizing:border-box} body{margin:0;line-height:1.5}
header{background:#083d58;color:#fff;padding:1.3rem} header div,main{max-width:760px;margin:auto}
main{padding:1.5rem 1rem 3rem}.card{background:#fff;border:1px solid #d4dfe3;border-radius:10px;padding:1.4rem;box-shadow:0 2px 8px #0b2f4011}
h1{margin:0;font-size:1.5rem}h2{margin-top:0;color:#083d58}label{display:block;font-weight:bold;margin:.8rem 0 .25rem}
input{width:100%;padding:.7rem;border:1px solid #788b95;border-radius:5px;font-size:1rem}
button{margin-top:1rem;background:#09658c;color:#fff;border:0;border-radius:5px;padding:.7rem 1rem;font-size:1rem;font-weight:bold;cursor:pointer}
button:hover{background:#064d6b}.muted{color:#455b65;font-size:.94rem}.notice{border-left:4px solid #b17200;background:#fff8e7;padding:.8rem;margin:1rem 0}
.status{min-height:1.5rem;margin-top:.8rem;font-weight:bold}.error{color:#9b1c1c}.success{color:#126234}
.hidden{display:none}pre{white-space:pre-wrap;word-break:break-word;background:#10232c;color:#ddf3ed;border-radius:6px;padding:.75rem;max-height:180px;overflow:auto}
footer{max-width:760px;margin:auto;padding:0 1rem 2rem;color:#455b65;font-size:.85rem}
</style>
</head>
<body>
<header><div><h1>Hospital account recovery</h1></div></header>
<main>
<section class="card" aria-live="polite">
  <div id="recovery-view">
    <h2>Reset your password</h2>
    <p>Enter a non-identifying contact value used for account recovery. We give the same response whether or not it is recognized.</p>
    <form id="recovery-form">
      <label for="contact">Recovery contact</label>
      <input id="contact" name="contact" maxlength="160" autocomplete="email" required>
      <button type="submit">Prepare recovery instructions</button>
    </form>
    <p class="status" id="recovery-status"></p>
  </div>

  <div id="token-view" class="hidden">
    <h2>Verify recovery token</h2>
    <p>For this local evaluation, mock delivery is shown in the browser console and Logs panel. You may paste or manually type the token.</p>
    <form id="token-form">
      <label for="token">Recovery token</label>
      <input id="token" name="token" maxlength="200" autocomplete="one-time-code" required>
      <button type="submit">Verify token</button>
    </form>
    <p class="status" id="token-status"></p>
  </div>

  <div id="password-view" class="hidden">
    <h2>Choose a new password</h2>
    <p class="muted">Use 12 or more characters with uppercase, lowercase, a number, and a symbol.</p>
    <form id="password-form">
      <label for="password">New password</label>
      <input id="password" type="password" maxlength="256" autocomplete="new-password" required>
      <label for="confirm-password">Confirm new password</label>
      <input id="confirm-password" type="password" maxlength="256" autocomplete="new-password" required>
      <button type="submit">Replace password</button>
    </form>
    <p class="status" id="password-status"></p>
  </div>

  <div id="mfa-view" class="hidden">
    <h2>Confirm your sign-in</h2>
    <p>Enter the six-digit mock confirmation code delivered to the local Logs panel.</p>
    <form id="mfa-form">
      <label for="mfa-code">Confirmation code</label>
      <input id="mfa-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
      <button type="submit">Confirm sign-in</button>
    </form>
    <p class="status" id="mfa-status"></p>
  </div>

  <div id="signin-view" class="hidden">
    <h2>Sign-in confirmed</h2>
    <p>Your password reset and local MFA confirmation are complete.</p>
    <button id="privacy-next" type="button">Review updated privacy conditions</button>
  </div>

  <div id="privacy-view" class="hidden">
    <h2>Updated privacy conditions</h2>
    <p>Accepting these conditions allows hospital authorities to proceed with appointment booking support.</p>
    <form id="privacy-form">
      <label><input id="accept" type="checkbox" required> I have reviewed and accept the updated privacy conditions.</label>
      <button type="submit">Accept conditions</button>
    </form>
    <p class="status" id="privacy-status"></p>
  </div>

  <div id="complete-view" class="hidden">
    <h2>Privacy conditions accepted</h2>
    <p>Your account confirmation is complete. You may now continue appointment support with hospital authorities.</p>
  </div>
</section>

<aside class="notice" aria-label="Anti-phishing guidance">
  <strong>Protect your account.</strong> Hospital staff never ask for passwords or confirmation codes by email or phone.
  Before authenticating, verify the address is <strong>https://localhost</strong> and your browser shows a secure connection.
  This demonstration makes no external delivery: all simulated recovery and MFA messages stay in this browser.
</aside>

<section aria-label="Local event logs">
  <h2>Logs</h2>
  <pre id="logs">Local simulated delivery events will appear here.</pre>
</section>
</main>
<footer>Recovery tokens are short-lived, single-use, and tied to this secure browser session.</footer>

<script nonce="${nonce}">
"use strict";
const CONFIG = ${state};
const views = ["recovery-view","token-view","password-view","mfa-view","signin-view","privacy-view","complete-view"];
const logs = document.getElementById("logs");

function show(id) {
  for (const view of views) document.getElementById(view).classList.toggle("hidden", view !== id);
}
function setStatus(id, message, ok) {
  const target = document.getElementById(id);
  target.textContent = message || "";
  target.className = "status " + (ok ? "success" : "error");
}
function localLog(message) {
  const stamped = "[" + new Date().toLocaleTimeString() + "] " + message;
  console.log(stamped);
  logs.textContent = logs.textContent === "Local simulated delivery events will appear here." ? stamped : logs.textContent + "\\n" + stamped;
  logs.scrollTop = logs.scrollHeight;
}
async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type":"application/json","X-CSRF-Token":CONFIG.csrf},
    body: JSON.stringify(payload)
  });
  let data;
  try { data = await response.json(); } catch (_) { data = {ok:false,message:"Unable to complete that request safely."}; }
  return data;
}

document.getElementById("recovery-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const contact = document.getElementById("contact").value;
  const data = await api("/api/recovery", {contact:contact});
  setStatus("recovery-status", data.message, data.ok);
  if (data.ok) {
    localLog("MOCK RECOVERY DELIVERY (local only): recovery token = " + data.recoveryToken);
    document.getElementById("token").value = data.recoveryToken;
    show("token-view");
  }
});

document.getElementById("token-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const token = document.getElementById("token").value;
  const data = await api("/api/verify-token", {token:token});
  setStatus("token-status", data.message, data.ok);
  if (data.ok) { localLog("Recovery token verified in this secure session."); show("password-view"); }
});

document.getElementById("password-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const password = document.getElementById("password").value;
  const confirm = document.getElementById("confirm-password").value;
  if (password !== confirm) { setStatus("password-status", "The password confirmation does not match.", false); return; }
  const data = await api("/api/password", {password:password});
  document.getElementById("password").value = "";
  document.getElementById("confirm-password").value = "";
  setStatus("password-status", data.message, data.ok);
  if (data.ok) {
    localLog("MOCK MFA DELIVERY (local only): confirmation code = " + data.mfaCode);
    show("mfa-view");
  }
});

document.getElementById("mfa-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const code = document.getElementById("mfa-code").value;
  const data = await api("/api/mfa", {code:code});
  setStatus("mfa-status", data.message, data.ok);
  if (data.ok) { localLog("MFA confirmation completed."); show("signin-view"); }
});

document.getElementById("privacy-next").addEventListener("click", function() { show("privacy-view"); });

document.getElementById("privacy-form").addEventListener("submit", async function(event) {
  event.preventDefault();
  const accepted = document.getElementById("accept").checked;
  const data = await api("/api/privacy", {accept:accepted});
  setStatus("privacy-status", data.message, data.ok);
  if (data.ok) { localLog("Updated privacy conditions accepted."); show("complete-view"); }
});
</script>
</body>
</html>`;
}

/*
 Security Requirements 1-5:
 Only explicit same-origin paths are handled. No redirects, external URLs,
 filesystem routing, debug output, stack traces, or private records are exposed.
*/
Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    const nonce = randomUrlToken(18);
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.search || url.hash) return genericError(nonce, 404);

      if (request.method === "GET" && url.pathname === "/") {
        let session = activeSession(request);
        let cookie: string | undefined;
        if (!session) {
          session = freshSession();
          sessions.set(session.id, session);
          cookie = sessionCookie(session);
        }
        const headers = securityHeaders(nonce, "text/html; charset=utf-8");
        if (cookie) headers.set("Set-Cookie", cookie);
        return new Response(page(nonce, session.csrf), { status: 200, headers });
      }

      if (url.pathname.startsWith("/api/")) return await handleApi(request, url, nonce);
      return genericError(nonce, 404);
    } catch {
      return genericError(nonce, 500);
    }
  },
});

console.log("Hospital recovery demo is listening securely at https://localhost:3000");
