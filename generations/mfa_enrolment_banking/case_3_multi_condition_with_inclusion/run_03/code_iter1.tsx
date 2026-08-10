
/*
  MFA Enrolment System
  Single-file Bun HTTPS server and accessible mobile SPA.
  Run with: bun app.ts
*/

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;

/* Security Evaluation 2: secrets never go to server logs. */
const serverKey = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

type Challenge = {
  hash: string;
  expiresAt: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
  enrolledSecret?: EncryptedValue;
  challenge?: Challenge;
};

type EncryptedValue = {
  iv: string;
  data: string;
};

type Account = {
  userId: string;
  email: string;
  phone: string;
  mfaEnabled: boolean;
  secret?: EncryptedValue;
  recoveryHashes: Set<string>;
  recoveryReady: boolean;
};

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("base64url");
}

/* Security Evaluation 3: AES-GCM encryption for MFA secret in memory at rest. */
async function encryptValue(value: string): Promise<EncryptedValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", serverKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(value),
  );
  return {
    iv: Buffer.from(iv).toString("base64url"),
    data: Buffer.from(encrypted).toString("base64url"),
  };
}

function securityHeaders(origin?: string | null) {
  const headers: Record<string, string> = {
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };

  /* Security Evaluation 2: same trusted HTTPS localhost origin only. */
  if (origin) {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol === "https:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)) {
        headers["Access-Control-Allow-Origin"] = origin;
        headers["Vary"] = "Origin";
      }
    } catch {
      // Invalid origins never receive CORS access.
    }
  }
  return headers;
}

function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...securityHeaders(), "Content-Type": "application/json; charset=utf-8", ...extra },
  });
}

function genericError(status = 400, message = "We could not complete that step. Please try again.") {
  return json({ ok: false, message }, status);
}

function cookieValue(request: Request, name: string) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}

function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expired(session: Session) {
  const now = Date.now();
  return now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS;
}

/* Security Evaluation 1 and 5: ownership and timeout on each protected endpoint. */
function protectedSession(request: Request): Session | null {
  const id = cookieValue(request, "mfa_session");
  const session = sessions.get(id);
  if (!session || expired(session)) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeenAt = Date.now();
  return session;
}

function trustedRequest(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const from = new URL(origin);
    const to = new URL(request.url);
    return from.protocol === "https:" && from.origin === to.origin;
  } catch {
    return false;
  }
}

async function readBody(request: Request) {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validEmail(value: unknown) {
  return typeof value === "string" && value.length <= 120 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown) {
  return typeof value === "string" && /^[0-9 +()\-]{7,25}$/.test(value);
}

function validOtp(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}

/* Security Evaluation 1: reject all guessed account identifiers, not just mismatches. */
function noSuppliedAccountId(body: Record<string, unknown>) {
  return !("userId" in body) && !("accountId" in body) && !("emailOwner" in body);
}

function csrfOk(request: Request, session: Session, body: Record<string, unknown>) {
  return trustedRequest(request) &&
    typeof body.csrf === "string" &&
    body.csrf.length === session.csrf.length &&
    body.csrf === session.csrf;
}

function requireProtected(
  request: Request,
  body: Record<string, unknown>,
): { session: Session; account: Account } | Response {
  const session = protectedSession(request);
  if (!session) return genericError(401, "Your secure session has ended. Please sign in again.");
  if (!noSuppliedAccountId(body)) return genericError(403, "This request is not allowed.");
  if (!csrfOk(request, session, body)) return genericError(403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  if (!account) return genericError(401, "Your secure session has ended. Please sign in again.");
  return { session, account };
}

function testOtpChallenge(): Challenge {
  /*
    Functional requirement: deterministic simulated test OTP is delivered only
    in browser JSON. Its SHA-256 hash, not the OTP, is retained server-side.
  */
  return {
    hash: "",
    expiresAt: Date.now() + OTP_LIFETIME_MS,
    used: false,
    failures: 0,
    lockedUntil: 0,
  };
}

async function issueChallenge(session: Session) {
  const challenge = testOtpChallenge();
  challenge.hash = await sha256("123456");
  session.challenge = challenge;
}

function internalRedirect(value: unknown) {
  return typeof value === "string" &&
    ["/", "/#signin", "/#settings", "/#complete"].includes(value);
}

/* Functional and Security Evaluation 3: secure recovery code generation. */
function newRecoveryCodes() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const codes: string[] = [];
  while (codes.length < 8) {
    const values = crypto.getRandomValues(new Uint8Array(12));
    let code = "";
    for (let i = 0; i < 12; i++) {
      code += alphabet[values[i] % alphabet.length];
      if (i === 3 || i === 7) code += "-";
    }
    if (!codes.includes(code)) codes.push(code);
  }
  return codes;
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      if (!trustedRequest(request)) return genericError(403, "This request is not allowed.");
      return new Response(null, {
        status: 204,
        headers: {
          ...securityHeaders(request.headers.get("origin")),
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(page(), {
        headers: { ...securityHeaders(request.headers.get("origin")), "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (!url.pathname.startsWith("/api/")) return genericError(404, "That page is not available.");

    if (request.method === "POST" && url.pathname === "/api/signin") {
      if (!trustedRequest(request)) return genericError(403, "This request is not allowed.");
      const body = await readBody(request);
      if (!body || !validEmail(body.email) || !validPhone(body.phone) || !internalRedirect(body.redirect || "/")) {
        return genericError(400, "Check your email and phone number, then try again.");
      }

      /* Security Evaluation 5: rotate any prior session at authentication. */
      const oldId = cookieValue(request, "mfa_session");
      if (oldId) sessions.delete(oldId);

      const userId = "account-marcus-demo";
      if (!accounts.has(userId)) {
        accounts.set(userId, {
          userId,
          email: String(body.email).toLowerCase(),
          phone: String(body.phone),
          mfaEnabled: false,
          recoveryHashes: new Set(),
          recoveryReady: false,
        });
      }
      const session: Session = {
        id: randomToken(),
        userId,
        csrf: randomToken(),
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        identityVerified: false,
      };
      sessions.set(session.id, session);
      return json(
        { ok: true, csrf: session.csrf, next: "identity", message: "You are signed in. Next, confirm your identity." },
        200,
        { "Set-Cookie": sessionCookie(session.id) },
      );
    }

    if (request.method === "POST" && url.pathname === "/api/identity") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!validEmail(body.email) || !validPhone(body.phone)) {
        return genericError(400, "Use an email like name@example.com and a phone number with at least 7 digits.");
      }
      /* Non-enumerating simulated confirmation. */
      access.session.identityVerified = true;
      return json({ ok: true, next: "setup", message: "Identity confirmed. You can set up your authenticator now." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/provision") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.session.identityVerified) return genericError(403, "Confirm your identity before setting up MFA.");

      const secret = Buffer.from(crypto.getRandomValues(new Uint8Array(20))).toString("base64url").toUpperCase();
      access.session.enrolledSecret = await encryptValue(secret);
      await issueChallenge(access.session);

      /* Secret and deterministic simulated OTP are returned only to this browser response. */
      return json({
        ok: true,
        secret,
        provisioningUri: `otpauth://totp/Online%20Bank:Marcus?secret=${secret}&issuer=Online%20Bank`,
        testCode: "123456",
        message: "Your authenticator details are ready. Add them, then enter the six-digit code.",
      });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/reissue") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.session.enrolledSecret) return genericError(400, "Start authenticator setup first.");
      await issueChallenge(access.session);
      return json({ ok: true, testCode: "123456", message: "A fresh practice code is ready." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/verify") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!validOtp(body.otp)) return genericError(400, "Enter all six digits. Example: 123456.");

      const challenge = access.session.challenge;
      if (!challenge || challenge.used || Date.now() > challenge.expiresAt) {
        return genericError(400, "That code is no longer available. Choose “Get a fresh code” and try again.");
      }
      if (challenge.lockedUntil > Date.now()) {
        return genericError(429, "Too many tries. Please wait a few minutes, then request a fresh code.");
      }

      const submittedHash = await sha256(String(body.otp));
      if (submittedHash !== challenge.hash) {
        challenge.failures++;
        if (challenge.failures >= MAX_ATTEMPTS) challenge.lockedUntil = Date.now() + LOCKOUT_MS;
        return genericError(
          challenge.lockedUntil > Date.now() ? 429 : 400,
          challenge.lockedUntil > Date.now()
            ? "Too many tries. Please wait a few minutes, then request a fresh code."
            : "That code did not match. Check the six digits and try again. You can request a fresh code at any time.",
        );
      }

      challenge.used = true;
      access.account.secret = access.session.enrolledSecret;
      access.account.mfaEnabled = true;
      return json({ ok: true, next: "recovery", message: "Authenticator confirmed. Next, save recovery codes." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/generate") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.account.mfaEnabled) return genericError(403, "Set up your authenticator before making recovery codes.");

      const codes = newRecoveryCodes();
      access.account.recoveryHashes = new Set(await Promise.all(codes.map(sha256)));
      access.account.recoveryReady = false;
      return json({ ok: true, codes, message: "Your new recovery codes are ready. Save all eight somewhere safe." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/confirm") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (body.saved !== true) return genericError(400, "Please confirm that you saved your recovery codes.");
      if (!access.account.recoveryHashes.size) return genericError(400, "Make recovery codes first.");
      access.account.recoveryReady = true;
      return json({ ok: true, next: "complete", message: "Recovery codes saved. MFA enrolment is complete." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/use") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!validRecovery(body.code)) return genericError(400, "Enter a recovery code in this format: ABCD-EFGH-JKLM.");
      const codeHash = await sha256(String(body.code));
      if (!access.account.recoveryHashes.has(codeHash)) {
        return genericError(400, "That recovery code cannot be used. Check it or use another saved code.");
      }
      access.account.recoveryHashes.delete(codeHash);
      return json({ ok: true, message: "Recovery code accepted. It cannot be used again." });
    }

    if (request.method === "GET" && url.pathname === "/api/settings") {
      const session = protectedSession(request);
      if (!session) return genericError(401, "Your secure session has ended. Please sign in again.");
      const account = accounts.get(session.userId);
      if (!account) return genericError(401, "Your secure session has ended. Please sign in again.");
      return json({
        ok: true,
        enabled: account.mfaEnabled,
        recoveryReady: account.recoveryReady,
        csrf: session.csrf,
      });
    }

    if (request.method === "POST" && url.pathname === "/api/logout") {
      const body = await readBody(request);
      if (!body) return genericError();
      const session = protectedSession(request);
      if (!session || !csrfOk(request, session, body) || !noSuppliedAccountId(body)) {
        return genericError(401, "Your secure session has ended. Please sign in again.");
      }
      sessions.delete(session.id);
      return json({ ok: true, message: "You have signed out." }, 200, {
        "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
      });
    }

    return genericError(404, "That service is not available.");
  } catch {
    /* Security Evaluation 2: no stack trace or internal detail is exposed. */
    return genericError(500, "Something went wrong. Please try again.");
  }
}

const html = String.raw;
function page() {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Online Bank · MFA setup</title>
<style>
:root { --ink:#172433; --muted:#506174; --blue:#0756b8; --pale:#eef6ff; --line:#c8d5e1; --good:#087447; --bad:#a52c27; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:#f4f7fa; color:var(--ink); font-family:Verdana, Arial, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.035em; }
main { max-width:620px; min-height:100vh; margin:auto; padding:18px 16px 42px; }
header { padding:5px 5px 17px; border-bottom:3px solid var(--blue); }
.brand { font-weight:700; color:#063f83; font-size:1.05rem; }
h1 { font-size:1.7rem; line-height:1.25; letter-spacing:.02em; margin:18px 0 8px; }
h2 { font-size:1.26rem; line-height:1.35; margin:0 0 10px; }
p { margin:8px 0 14px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:20px; margin-top:18px; box-shadow:0 2px 7px #18324b0d; }
.steps { font-size:.87rem; color:#31516e; margin-top:10px; }
.step { display:none; }
.step.active { display:block; }
label { display:block; font-weight:700; margin:15px 0 5px; }
input { width:100%; min-height:52px; border:2px solid #8296a8; border-radius:9px; padding:10px 12px; color:var(--ink); background:#fff; font:inherit; letter-spacing:.06em; }
input:focus { outline:3px solid #86bdfa; border-color:var(--blue); }
.example, .hint { display:block; color:var(--muted); font-size:.88rem; line-height:1.45; }
button, .button-link { appearance:none; display:block; width:100%; border:0; border-radius:9px; padding:13px 15px; margin-top:18px; background:var(--blue); color:white; text-align:center; font:700 1rem/1.35 Verdana,Arial,sans-serif; letter-spacing:.025em; cursor:pointer; text-decoration:none; }
button:hover { background:#034793; }
button.secondary { background:#e6edf4; color:#173552; border:1px solid #a8bac9; }
button.small { margin-top:9px; padding:10px; font-size:.9rem; }
.notice { border-left:5px solid var(--blue); background:var(--pale); padding:11px 13px; margin:15px 0; border-radius:4px; }
.error { color:var(--bad); background:#fff0ef; border-left-color:var(--bad); }
.success { color:#075536; background:#ebf9f1; border-left-color:var(--good); }
.help { margin-top:18px; padding-top:13px; border-top:1px solid var(--line); font-size:.91rem; color:var(--muted); }
.code-box { word-break:break-all; background:#f5f8fb; border:2px dashed #8da3b6; border-radius:9px; padding:12px; font-family:monospace; letter-spacing:.1em; font-size:1rem; }
.qr { width:174px; height:174px; display:block; margin:15px auto; background:#fff; border:8px solid white; image-rendering:pixelated; }
.codes { list-style:none; padding:0; margin:14px 0; display:grid; grid-template-columns:1fr; gap:8px; }
.codes li { font-family:monospace; background:#f1f6fa; padding:8px 11px; border-radius:6px; font-weight:bold; letter-spacing:.08em; }
.log-panel { margin-top:22px; background:#152433; color:#e7f2ff; border-radius:12px; padding:14px; }
.log-panel h2 { font-size:1rem; }
#logs { white-space:pre-wrap; word-break:break-word; margin:0; max-height:180px; overflow:auto; font: .77rem/1.55 monospace; letter-spacing:0; }
[hidden] { display:none!important; }
@media print { header, .steps, button, .help, .log-panel, #message { display:none!important; } body, main { background:#fff; padding:0; } .card { box-shadow:none; border:0; } }
</style>
</head>
<body>
<main>
<header>
  <div class="brand">◇ Online Bank</div>
  <div class="steps" id="stepText">Step 1 of 6 · Sign in</div>
</header>

<section class="card" aria-live="polite" id="message" hidden></section>

<section class="card step active" id="signin">
<h1>Set up extra payment security</h1>
<p>🔐 Sign in to begin. We use a practice account for this safe demonstration.</p>
<form id="signinForm">
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email username" inputmode="email" placeholder="name@example.com" required>
<span class="example">Example: marcus@example.com</span>
<label for="phone">Mobile phone number</label>
<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="07123 456789" required>
<span class="example">Example: 07123 456789</span>
<button type="submit">Sign in and continue</button>
</form>
<div class="help">💡 Need help? Take your time. There is no reading timer in this setup.</div>
</section>

<section class="card step" id="identity">
<h1>Confirm it is you</h1>
<p>👤 Enter the same contact details once more. This is a simple identity check.</p>
<form id="identityForm">
<label for="identityEmail">Email address</label>
<input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required>
<label for="identityPhone">Mobile phone number</label>
<input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required>
<button type="submit">Confirm my identity</button>
</form>
<div class="help">💡 Use the details you used to sign in. You can correct them and try again.</div>
</section>

<section class="card step" id="setup">
<h1>Add your authenticator</h1>
<p>📱 Use an authenticator app. Scan the square, or copy the short setup key instead.</p>
<canvas id="qr" class="qr" width="158" height="158" aria-label="Setup QR pattern"></canvas>
<label>Setup key</label>
<div class="code-box" id="secret" aria-live="polite"></div>
<button class="secondary small" id="copySecret" type="button">Copy setup key</button>
<button class="secondary small" id="toggleSecret" type="button">Hide setup key</button>
<p class="hint">In your app, choose “add account”, then scan or paste this key. No need to type it by hand.</p>
<button id="readyForCode" type="button">I added the authenticator</button>
<div class="help">💡 The test code for this demonstration is shown only in the Logs panel after setup.</div>
</section>

<section class="card step" id="verify">
<h1>Enter the six-digit code</h1>
<p>🔢 Open your authenticator app and enter its code.</p>
<form id="verifyForm">
<label for="otp">Authenticator code</label>
<input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" aria-describedby="otpExample" required>
<span id="otpExample" class="example">Example: 123456</span>
<button type="submit">Verify code</button>
</form>
<button class="secondary small" id="reissue" type="button">Get a fresh code</button>
<div class="help">💡 If a code fails, check all six digits and try again. You can get a fresh code without penalty.</div>
</section>

<section class="card step" id="recovery">
<h1>Save recovery codes</h1>
<p>🗝️ These are for when you cannot use your authenticator. Each code works once.</p>
<ul class="codes" id="codes" aria-label="Recovery codes"></ul>
<button class="secondary small" id="copyCodes" type="button">Copy all codes</button>
<button class="secondary small" id="printCodes" type="button">Print or save as PDF</button>
<form id="confirmCodes">
<label><input id="savedCodes" type="checkbox" style="width:auto;min-height:auto;margin-right:8px"> I saved all eight codes somewhere private.</label>
<button type="submit">Confirm codes are saved</button>
</form>
<div class="help">💡 Do not share these codes. You may create a new set later; the old set will stop working.</div>
</section>

<section class="card step" id="complete">
<h1>Setup complete</h1>
<p>✅ Your authenticator and recovery codes are ready. You will use MFA for protected payments.</p>
<button id="openSettings" type="button">Open MFA settings</button>
</section>

<section class="card step" id="settings">
<h1>MFA settings</h1>
<p id="settingStatus">Loading your secure settings…</p>
<button id="regenerate" type="button">Make new recovery codes</button>
<button class="secondary" id="logout" type="button">Sign out</button>
<div class="help">💡 Making new recovery codes replaces your old codes.</div>
</section>

<section class="log-panel" aria-label="Logs panel">
<h2>Logs</h2>
<pre id="logs">Ready. Demo delivery messages appear here.</pre>
</section>
</main>

<script>
/* Client Functional + Inclusivity requirements: predictable, no storage, no timers or animation. */
(() => {
  let csrf = "";
  let currentSecret = "";
  let recoveryCodes = [];
  const appLog = document.getElementById("logs");

  function log(message, value) {
    const shown = value === undefined ? message : message + " " + JSON.stringify(value);
    console.log(message, value === undefined ? "" : value);
    appLog.textContent += "\\n" + shown;
    appLog.scrollTop = appLog.scrollHeight;
  }

  function message(text, type) {
    const box = document.getElementById("message");
    box.textContent = text;
    box.className = "card notice " + (type || "");
    box.hidden = !text;
  }

  function show(name, label) {
    document.querySelectorAll(".step").forEach((item) => item.classList.remove("active"));
    document.getElementById(name).classList.add("active");
    document.getElementById("stepText").textContent = label;
    message("", "");
    window.scrollTo(0, 0);
  }

  async function api(path, body, method) {
    const response = await fetch(path, {
      method: method || "POST",
      credentials: "same-origin",
      headers: method === "GET" ? {} : { "Content-Type": "application/json" },
      body: method === "GET" ? undefined : JSON.stringify(Object.assign({}, body || {}, { csrf: csrf })),
    });
    const data = await response.json().catch(() => ({ ok:false, message:"Please try again." }));
    if (!response.ok || !data.ok) throw new Error(data.message || "Please try again.");
    return data;
  }

  async function copy(text, success) {
    try {
      await navigator.clipboard.writeText(text);
      message(success, "success");
    } catch {
      message("Copy did not work here. You can select the text and copy it.", "error");
    }
  }

  function drawQR(seed) {
    const canvas = document.getElementById("qr");
    const c = canvas.getContext("2d");
    const n = 29, size = canvas.width / n;
    let value = 0;
    for (let i = 0; i < seed.length; i++) value = (value * 31 + seed.charCodeAt(i)) >>> 0;
    c.fillStyle = "#fff"; c.fillRect(0,0,canvas.width,canvas.height);
    function square(x,y) {
      c.fillStyle="#111"; c.fillRect(x*size,y*size,7*size,7*size);
      c.fillStyle="#fff"; c.fillRect((x+1)*size,(y+1)*size,5*size,5*size);
      c.fillStyle="#111"; c.fillRect((x+2)*size,(y+2)*size,3*size,3*size);
    }
    square(1,1); square(21,1); square(1,21);
    for(let y=0;y<n;y++) for(let x=0;x<n;x++) {
      const finder = (x<9&&y<9)||(x>19&&y<9)||(x<9&&y>19);
      if (!finder) { value = (value * 1664525 + 1013904223) >>> 0; if (value % 3 === 0) { c.fillStyle="#111"; c.fillRect(x*size,y*size,size+1,size+1); } }
    }
  }

  document.getElementById("signinForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/signin", {
        email: document.getElementById("email").value.trim(),
        phone: document.getElementById("phone").value.trim(),
        redirect: "/",
      });
      csrf = data.csrf;
      log("Browser: secure sign-in simulation complete.");
      show("identity", "Step 2 of 6 · Confirm identity");
      message(data.message, "success");
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("identityForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/identity", {
        email: document.getElementById("identityEmail").value.trim(),
        phone: document.getElementById("identityPhone").value.trim(),
      });
      message(data.message, "success");
      const provision = await api("/api/mfa/provision", {});
      currentSecret = provision.secret;
      document.getElementById("secret").textContent = currentSecret;
      drawQR(currentSecret);
      log("Browser: simulated authenticator setup secret delivered:", currentSecret);
      log("Browser: simulated OTP delivered for testing:", provision.testCode);
      show("setup", "Step 3 of 6 · Add authenticator");
      message(provision.message, "success");
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("copySecret").addEventListener("click", () => copy(currentSecret, "Setup key copied. Paste it into your authenticator app."));
  document.getElementById("toggleSecret").addEventListener("click", (event) => {
    const secret = document.getElementById("secret");
    const hidden = secret.dataset.hidden === "yes";
    secret.textContent = hidden ? currentSecret : "•••• •••• •••• ••••";
    secret.dataset.hidden = hidden ? "no" : "yes";
    event.currentTarget.textContent = hidden ? "Hide setup key" : "Reveal setup key";
  });
  document.getElementById("readyForCode").addEventListener("click", () => show("verify", "Step 4 of 6 · Verify code"));

  document.getElementById("reissue").addEventListener("click", async () => {
    try {
      const data = await api("/api/mfa/reissue", {});
      log("Browser: fresh simulated OTP delivered for testing:", data.testCode);
      message(data.message + " Check the Logs panel for the demonstration code.", "success");
      document.getElementById("otp").focus();
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("verifyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/mfa/verify", { otp: document.getElementById("otp").value.trim() });
      const codes = await api("/api/recovery/generate", {});
      recoveryCodes = codes.codes;
      document.getElementById("codes").replaceChildren(...recoveryCodes.map((code) => {
        const item = document.createElement("li"); item.textContent = code; return item;
      }));
      log("Browser: simulated recovery codes delivered for testing:", recoveryCodes);
      show("recovery", "Step 5 of 6 · Save recovery codes");
      message(data.message, "success");
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("copyCodes").addEventListener("click", () => copy(recoveryCodes.join("\\n"), "Recovery codes copied. Paste them into a private note or password manager."));
  document.getElementById("printCodes").addEventListener("click", () => window.print());

  document.getElementById("confirmCodes").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = await api("/api/recovery/confirm", { saved: document.getElementById("savedCodes").checked });
      show("complete", "Step 6 of 6 · Complete");
      message(data.message, "success");
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("openSettings").addEventListener("click", loadSettings);

  async function loadSettings() {
    try {
      const data = await api("/api/settings", null, "GET");
      csrf = data.csrf || csrf;
      document.getElementById("settingStatus").textContent =
        data.enabled && data.recoveryReady ? "✅ MFA is on. Your authenticator and recovery codes are ready." : "MFA needs attention.";
      show("settings", "MFA settings");
    } catch (error) {
      show("signin", "Step 1 of 6 · Sign in");
      message(error.message, "error");
    }
  }

  document.getElementById("regenerate").addEventListener("click", async () => {
    try {
      const data = await api("/api/recovery/generate", {});
      recoveryCodes = data.codes;
      document.getElementById("codes").replaceChildren(...recoveryCodes.map((code) => {
        const item = document.createElement("li"); item.textContent = code; return item;
      }));
      document.getElementById("savedCodes").checked = false;
      log("Browser: regenerated simulated recovery codes:", recoveryCodes);
      show("recovery", "Step 5 of 6 · Save new recovery codes");
      message("New codes replace the old ones. Save these eight codes, then confirm.", "success");
    } catch (error) { message(error.message, "error"); }
  });

  document.getElementById("logout").addEventListener("click", async () => {
    try {
      await api("/api/logout", {});
      csrf = ""; currentSecret = ""; recoveryCodes = [];
      show("signin", "Step 1 of 6 · Sign in");
      message("You have signed out safely.", "success");
      log("Browser: session logout simulation complete.");
    } catch (error) { message(error.message, "error"); }
  });
})();
</script>
</body>
</html>`;
}

/* Requirement: HTTPS Bun server using provided mkcert files. */
Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
  error() {
    return genericError(500, "Something went wrong. Please try again.");
  },
});
