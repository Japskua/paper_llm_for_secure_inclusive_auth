
const encoder = new TextEncoder();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const serverPepper = crypto.getRandomValues(new Uint8Array(32));

type SessionPhase = "pending" | "authenticated";
type EncryptedValue = { iv: string; ciphertext: string };
type BackupCode = { hash: string; used: boolean };

type Session = {
  id: string;
  ownerId: string;
  phase: SessionPhase;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityCodeHash?: string;
  identityExpiresAt?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockUntil: number;
  totpFailures: number;
  totpLockUntil: number;
  mfaSecret?: EncryptedValue;
  mfaStatus: "none" | "provisioning" | "active";
  lastTotpCounter?: number;
  backupCodes: BackupCode[];
};

const sessions = new Map<string, Session>();
const ACCOUNT_OWNER_ID = "account-owner-marcus";
const SESSION_COOKIE = "__Host-mfa_session";
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const IDENTITY_CODE_LIFETIME_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const allowedPaths = new Set([
  "/",
  "/api/session",
  "/api/signin",
  "/api/identity/verify",
  "/api/mfa/provision",
  "/api/mfa/activate",
  "/api/mfa/backup/regenerate",
  "/api/mfa/backup/acknowledge",
  "/api/mfa/recovery/verify",
  "/api/logout",
]);

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function secureInt(maxExclusive: number): number {
  const max = 0x100000000;
  const limit = max - (max % maxExclusive);
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value);
  while (value[0] >= limit);
  return value[0] % maxExclusive;
}

function sixDigitCode(): string {
  return String(secureInt(1_000_000)).padStart(6, "0");
}

function cookieHeader(value: string, maxAge?: number): string {
  const expires = maxAge === 0 ? "; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT" : "";
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${expires}`;
}

function parseCookies(req: Request): Record<string, string> {
  const raw = req.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const at = part.indexOf("=");
    if (at > 0) output[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return output;
}

function allowedOrigin(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try {
    const requestURL = new URL(req.url);
    const supplied = new URL(origin);
    return supplied.protocol === "https:" &&
      supplied.origin === requestURL.origin &&
      (supplied.hostname === "localhost" || supplied.hostname === "127.0.0.1" || supplied.hostname === "[::1]");
  } catch {
    return false;
  }
}

// Requirements 1 and 5: session ownership, expiry, and authenticated-only server resolution.
function getSession(req: Request, requiredPhase?: SessionPhase): Session | null {
  const id = parseCookies(req)[SESSION_COOKIE];
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;

  const now = Date.now();
  if (now - session.lastSeenAt > IDLE_TIMEOUT_MS || now - session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    sessions.delete(id);
    return null;
  }
  if (requiredPhase && session.phase !== requiredPhase) return null;
  session.lastSeenAt = now;
  return session;
}

// Requirements 1 and 5: anti-CSRF token is bound to the opaque HttpOnly-cookie session.
function csrfValid(req: Request, session: Session): boolean {
  const token = req.headers.get("x-csrf-token");
  return typeof token === "string" && token.length === session.csrf.length &&
    token === session.csrf && allowedOrigin(req);
}

async function hashValue(value: string): Promise<string> {
  const material = new Uint8Array(serverPepper.length + encoder.encode(value).length);
  material.set(serverPepper);
  material.set(encoder.encode(value), serverPepper.length);
  const digest = await crypto.subtle.digest("SHA-256", material);
  return Buffer.from(digest).toString("hex");
}

// Requirement 3: OTP seed is AES-GCM protected while resident in server memory.
async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const key = await crypto.subtle.importKey("raw", masterKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return {
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(encrypted).toString("base64"),
  };
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64") },
    key,
    Buffer.from(value.ciphertext, "base64"),
  );
  return new TextDecoder().decode(plain);
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function generateBase32Secret(length = 32): string {
  let result = "";
  for (let i = 0; i < length; i++) result += BASE32[secureInt(BASE32.length)];
  return result;
}

function decodeBase32(text: string): Uint8Array {
  let bits = "";
  for (const character of text.replace(/=+$/g, "").toUpperCase()) {
    const index = BASE32.indexOf(character);
    if (index < 0) throw new Error("invalid secret");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

// Requirement 5: standards-compatible, time-windowed TOTP validation.
async function totpFor(secret: string, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let counterValue = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(counterValue & 255n);
    counterValue >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const number = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}

function newRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  for (let i = 0; i < 16; i++) {
    if (i === 4 || i === 8 || i === 12) value += "-";
    value += alphabet[secureInt(alphabet.length)];
  }
  return value;
}

async function createBackupCodes(): Promise<{ visible: string[]; stored: BackupCode[] }> {
  const visible: string[] = [];
  const stored: BackupCode[] = [];
  for (let i = 0; i < 8; i++) {
    const code = newRecoveryCode();
    visible.push(code);
    stored.push({ hash: await hashValue(code), used: false });
  }
  return { visible, stored };
}

// Requirements 2 and 4: restrictive headers, no debug error data, and trusted CORS only.
function headersFor(req: Request, extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Vary", "Origin");
  const origin = req.headers.get("origin");
  if (origin && allowedOrigin(req)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
  }
  return headers;
}

function json(req: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = headersFor(req, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(req: Request, status = 400): Response {
  return json(req, { ok: false, message: "We could not complete that request. Please try again." }, status);
}

async function requestBody(req: Request): Promise<Record<string, unknown> | null> {
  const contentType = req.headers.get("content-type") || "";
  const length = Number(req.headers.get("content-length") || "0");
  if (!contentType.includes("application/json") || length > 10_000) return null;
  try {
    const data = await req.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function createPendingSession(code: string): Promise<Session> {
  const now = Date.now();
  return hashValue(code).then((identityCodeHash) => ({
    id: randomToken(),
    ownerId: ACCOUNT_OWNER_ID,
    phase: "pending",
    csrf: randomToken(),
    createdAt: now,
    lastSeenAt: now,
    identityCodeHash,
    identityExpiresAt: now + IDENTITY_CODE_LIFETIME_MS,
    identityUsed: false,
    identityFailures: 0,
    identityLockUntil: 0,
    totpFailures: 0,
    totpLockUntil: 0,
    mfaStatus: "none",
    backupCodes: [],
  }));
}

function rotateAuthenticatedSession(pending: Session): Session {
  const now = Date.now();
  return {
    id: randomToken(),
    ownerId: pending.ownerId,
    phase: "authenticated",
    csrf: randomToken(),
    createdAt: now,
    lastSeenAt: now,
    identityFailures: 0,
    identityLockUntil: 0,
    totpFailures: 0,
    totpLockUntil: 0,
    mfaStatus: "none",
    backupCodes: [],
  };
}

function appHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>Northstar Bank MFA enrolment</title>
<style>
:root{--navy:#102a43;--blue:#1769aa;--pale:#eef6fc;--ink:#17212b;--muted:#536574;--danger:#a61b1b;--line:#c9d6df;--ok:#126b42}
*{box-sizing:border-box} body{margin:0;background:#f4f7f9;color:var(--ink);font:17px/1.48 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:var(--navy);color:#fff;padding:18px max(18px,calc((100vw - 600px)/2));box-shadow:0 2px 5px #0003} header strong{font-size:1.15rem} header p{margin:2px 0 0;font-size:.9rem;color:#d9e9f5}
main,aside{width:min(100%,600px);margin:0 auto;padding:20px 18px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 2px 8px #102a4310}
h1{font-size:1.55rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.2rem;margin:22px 0 8px}p{margin:8px 0 16px}.help{color:var(--muted);font-size:.94rem}.notice{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;border-radius:5px;margin:14px 0}.error{color:var(--danger);font-weight:650;min-height:1.5em}.success{color:var(--ok);font-weight:650}
label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;font:inherit;padding:12px;border:2px solid #879aa8;border-radius:8px;background:#fff}input:focus,button:focus{outline:3px solid #f6b73c;outline-offset:2px}button{font:inherit;font-weight:700;border:0;border-radius:8px;padding:12px 16px;margin:12px 6px 0 0;cursor:pointer;background:var(--blue);color:#fff;min-height:48px}button.secondary{background:#e4edf3;color:var(--navy)}button.danger{background:#8c2020}button:disabled{opacity:.6;cursor:wait}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;background:#f1f4f6;padding:10px;border-radius:6px}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:ui-monospace,monospace;font-size:1.04rem;background:#f1f4f6;margin:7px 0;padding:9px 11px;border-radius:6px;letter-spacing:.04em}aside{padding-top:0}details{background:#152f42;color:#ecf6ff;border-radius:10px;padding:10px 14px}summary{font-weight:700;cursor:pointer}.logs{max-height:170px;overflow:auto;font:12px/1.45 ui-monospace,monospace;white-space:pre-wrap;color:#d8f3ff;padding:8px 0}.sr-only{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}
@media(max-width:380px){body{font-size:16px}.card{padding:17px}main,aside{padding-left:12px;padding-right:12px}}
</style>
</head>
<body>
<header><strong>Northstar Bank</strong><p>Secure MFA enrolment</p></header>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<aside aria-label="Test logs"><details open><summary>Logs (test-only simulated delivery)</summary><div id="logs" class="logs" role="log" aria-live="polite"></div></details></aside>
<script>
(() => {
  "use strict";
  let csrf = "";
  let route = "signin";
  let provision = null;
  let visibleCodes = null;
  const app = document.getElementById("app");
  const logPanel = document.getElementById("logs");

  // Requirement deliverable: simulated delivery exists only in browser console and visible test log.
  function log(message) {
    console.log(message);
    const line = document.createElement("div");
    line.textContent = message;
    logPanel.appendChild(line);
    logPanel.scrollTop = logPanel.scrollHeight;
  }

  async function api(path, method, body, needsCsrf) {
    const headers = {"Content-Type":"application/json"};
    if (needsCsrf && csrf) headers["X-CSRF-Token"] = csrf;
    let response;
    try {
      response = await fetch(path, {method, headers, credentials:"same-origin", body: body ? JSON.stringify(body) : undefined});
    } catch (_) {
      return {ok:false, message:"Connection unavailable. Please try again."};
    }
    let data;
    try { data = await response.json(); } catch (_) { return {ok:false, message:"We could not complete that request. Please try again."}; }
    return data;
  }

  function message(node, text, okay) {
    node.textContent = text || "";
    node.className = okay ? "success" : "error";
  }

  function renderSignIn() {
    app.innerHTML = '<section class="card" aria-labelledby="title"><h1 id="title">Set up secure sign-in</h1><p>Before payments above your limit can be approved, verify your identity and add an authenticator.</p><div class="notice">Use an email and phone number you can access. We will send a test verification code in this demonstration.</div><form id="sign-form" novalidate><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" inputmode="email" required><label for="phone">Mobile phone number</label><input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" required><p id="form-message" class="error" role="alert"></p><button type="submit">Continue to identity check</button></form></section>';
    document.getElementById("sign-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = form.querySelector("button");
      const status = document.getElementById("form-message");
      button.disabled = true;
      const result = await api("/api/signin", "POST", {
        email: document.getElementById("email").value.trim(),
        phone: document.getElementById("phone").value.trim()
      }, false);
      button.disabled = false;
      if (!result.ok) return message(status, result.message, false);
      csrf = result.csrf;
      // Test-only mock; no browser storage, URL, or server log is used.
      log("TEST ONLY — simulated identity verification code: " + result.mockCode);
      route = "verify";
      render();
    });
  }

  function renderVerify() {
    app.innerHTML = '<section class="card" aria-labelledby="verify-title"><h1 id="verify-title">Verify your identity</h1><p>Enter the six-digit code sent to your phone.</p><p class="help">For this academic demo, the simulated code is in the Logs panel and browser console. It expires in five minutes and can be used once.</p><form id="verify-form" novalidate><label for="identity-code">Verification code</label><input id="identity-code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><p id="verify-message" class="error" role="alert"></p><button type="submit">Verify identity</button><button type="button" class="secondary" id="back">Start again</button></form></section>';
    document.getElementById("back").onclick = () => { route = "signin"; csrf = ""; render(); };
    document.getElementById("verify-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const status = document.getElementById("verify-message");
      const result = await api("/api/identity/verify", "POST", {code: document.getElementById("identity-code").value.trim()}, true);
      if (!result.ok) return message(status, result.message, false);
      csrf = result.csrf;
      route = "enrol";
      log("Identity verification completed.");
      render();
    });
  }

  function renderEnrol() {
    app.innerHTML = '<section class="card" aria-labelledby="enrol-title"><h1 id="enrol-title">Add an authenticator app</h1><p>An authenticator app produces a new code every 30 seconds. This protects high-value payments.</p><div class="notice"><strong>Accessible option:</strong> you can enter the setup secret manually in your authenticator app. A QR code is not required.</div><p id="enrol-message" class="error" role="alert"></p><button id="create">Create authenticator setup</button><button class="secondary" id="logout">Log out</button></section>';
    document.getElementById("logout").onclick = logout;
    document.getElementById("create").onclick = async (event) => {
      event.currentTarget.disabled = true;
      const result = await api("/api/mfa/provision", "POST", {}, true);
      if (!result.ok) {
        event.currentTarget.disabled = false;
        return message(document.getElementById("enrol-message"), result.message, false);
      }
      provision = result;
      // Requirement test mock delivery: provisioning data is never written to persistent storage.
      log("TEST ONLY — authenticator manual secret: " + result.manualSecret);
      log("TEST ONLY — authenticator provisioning URI: " + result.provisioningUri);
      log("TEST ONLY — current authenticator code: " + result.mockCurrentCode);
      route = "activate";
      render();
    };
  }

  function renderActivate() {
    if (!provision) { route = "enrol"; return render(); }
    app.innerHTML = '<section class="card" aria-labelledby="activate-title"><h1 id="activate-title">Connect your authenticator</h1><p>In your authenticator app, choose to add an account manually and enter this setup secret:</p><p id="secret" class="mono" aria-label="Manual authenticator setup secret"></p><p class="help">Account: Northstar Bank (Marcus). The secret is shown only during setup.</p><label for="totp">Authenticator code</label><input id="totp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"><p id="activate-message" class="error" role="alert"></p><button id="activate">Activate MFA</button><button class="secondary" id="cancel">Cancel setup</button></section>';
    document.getElementById("secret").textContent = provision.manualSecret;
    document.getElementById("cancel").onclick = () => { provision = null; route = "enrol"; render(); };
    document.getElementById("activate").onclick = async (event) => {
      event.currentTarget.disabled = true;
      const result = await api("/api/mfa/activate", "POST", {code: document.getElementById("totp").value.trim()}, true);
      if (!result.ok) {
        event.currentTarget.disabled = false;
        return message(document.getElementById("activate-message"), result.message, false);
      }
      provision = null;
      visibleCodes = result.backupCodes;
      log("TEST ONLY — newly issued backup recovery codes: " + result.backupCodes.join(", "));
      route = "codes";
      render();
    };
  }

  function renderCodes() {
    if (!Array.isArray(visibleCodes)) { route = "home"; return render(); }
    app.innerHTML = '<section class="card" aria-labelledby="codes-title"><h1 id="codes-title">Save your recovery codes</h1><p>These one-use codes can recover access if you lose your authenticator. Store them somewhere private. They are displayed only once.</p><ul id="code-list" class="codes" aria-label="Backup recovery codes"></ul><div class="notice">Do not share these codes with anyone, including bank staff.</div><p id="codes-message" class="error" role="alert"></p><button id="saved">I have saved these codes</button></section>';
    const list = document.getElementById("code-list");
    visibleCodes.forEach((code) => { const li = document.createElement("li"); li.textContent = code; list.appendChild(li); });
    document.getElementById("saved").onclick = async () => {
      const result = await api("/api/mfa/backup/acknowledge", "POST", {}, true);
      if (!result.ok) return message(document.getElementById("codes-message"), result.message, false);
      visibleCodes = null;
      route = "home";
      render();
    };
  }

  function renderHome() {
    app.innerHTML = '<section class="card" aria-labelledby="home-title"><h1 id="home-title">MFA is active</h1><p class="success">Your authenticator is ready for protected payments.</p><h2>Use a recovery code</h2><p class="help">A recovery code is accepted once and then disabled.</p><form id="recovery-form"><label for="recovery-code">Recovery code</label><input id="recovery-code" type="text" autocomplete="off" autocapitalize="characters" placeholder="ABCD-EFGH-IJKL-MNPQ"><p id="recovery-message" class="error" role="alert"></p><button type="submit">Verify recovery code</button></form><h2>Need a new set?</h2><p class="help">Generating new codes permanently invalidates all previous recovery codes.</p><button class="secondary" id="regenerate">Generate new recovery codes</button><button class="danger" id="logout">Log out</button></section>';
    document.getElementById("logout").onclick = logout;
    document.getElementById("recovery-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const result = await api("/api/mfa/recovery/verify", "POST", {code: document.getElementById("recovery-code").value.trim()}, true);
      message(document.getElementById("recovery-message"), result.message, result.ok);
      if (result.ok) log("A recovery code was accepted and is now single-use consumed.");
    });
    document.getElementById("regenerate").onclick = async (event) => {
      event.currentTarget.disabled = true;
      const result = await api("/api/mfa/backup/regenerate", "POST", {}, true);
      if (!result.ok) {
        event.currentTarget.disabled = false;
        return;
      }
      visibleCodes = result.backupCodes;
      log("TEST ONLY — regenerated backup recovery codes: " + result.backupCodes.join(", "));
      route = "codes";
      render();
    };
  }

  async function logout() {
    await api("/api/logout", "POST", {}, true);
    csrf = ""; provision = null; visibleCodes = null; route = "signin";
    log("Signed out. The secure session was invalidated.");
    render();
  }

  function render() {
    if (route === "signin") renderSignIn();
    else if (route === "verify") renderVerify();
    else if (route === "enrol") renderEnrol();
    else if (route === "activate") renderActivate();
    else if (route === "codes") renderCodes();
    else renderHome();
  }

  async function boot() {
    const state = await api("/api/session", "GET", null, false);
    if (state.ok) {
      csrf = state.csrf || "";
      route = state.phase === "pending" ? "verify" : (state.mfaStatus === "active" ? "home" : "enrol");
    }
    render();
  }
  boot();
})();
</script>
</body>
</html>`;
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);

  // Requirement 2: Bun is TLS-only below; reject malformed/non-allow-listed routes.
  if (url.protocol !== "https:" || !allowedPaths.has(url.pathname) || url.search) {
    return genericError(req, 404);
  }

  if (req.method === "OPTIONS") {
    if (!allowedOrigin(req)) return genericError(req, 403);
    const headers = headersFor(req);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Max-Age", "600");
    return new Response(null, { status: 204, headers });
  }

  if (url.pathname === "/" && req.method === "GET") {
    const headers = headersFor(req);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(appHtml(), { status: 200, headers });
  }

  if (url.pathname === "/api/session" && req.method === "GET") {
    const session = getSession(req);
    if (!session) return json(req, { ok: true, phase: "signedout" });
    return json(req, {
      ok: true,
      phase: session.phase,
      csrf: session.csrf,
      mfaStatus: session.mfaStatus,
    });
  }

  if (req.method !== "POST" || !allowedOrigin(req)) return genericError(req, 403);
  const body = await requestBody(req);
  if (!body) return genericError(req);

  if (url.pathname === "/api/signin") {
    // Requirements 4 and 5: strict input validation and intentionally generic sign-in result.
    if (!validEmail(body.email) || !validPhone(body.phone)) return genericError(req);
    const verificationCode = sixDigitCode();
    const pending = await createPendingSession(verificationCode);
    sessions.set(pending.id, pending);
    return json(req, {
      ok: true,
      csrf: pending.csrf,
      mockCode: verificationCode,
      message: "If the details can be used, a verification code has been sent.",
    }, 200, { "Set-Cookie": cookieHeader(pending.id) });
  }

  if (url.pathname === "/api/identity/verify") {
    const pending = getSession(req, "pending");
    if (!pending || !csrfValid(req, pending)) return genericError(req, 403);
    const now = Date.now();
    if (pending.identityLockUntil > now) return genericError(req, 429);
    if (!validOtp(body.code) || pending.identityUsed || !pending.identityExpiresAt || now > pending.identityExpiresAt ||
      await hashValue(String(body.code)) !== pending.identityCodeHash) {
      pending.identityFailures++;
      if (pending.identityFailures >= 5) pending.identityLockUntil = now + LOCKOUT_MS;
      return genericError(req, pending.identityLockUntil > now ? 429 : 400);
    }
    pending.identityUsed = true;
    const authenticated = rotateAuthenticatedSession(pending);
    sessions.delete(pending.id);
    sessions.set(authenticated.id, authenticated);
    return json(req, { ok: true, csrf: authenticated.csrf }, 200, {
      "Set-Cookie": cookieHeader(authenticated.id),
    });
  }

  if (url.pathname === "/api/logout") {
    const session = getSession(req);
    if (!session || !csrfValid(req, session)) return genericError(req, 403);
    sessions.delete(session.id);
    return json(req, { ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });
  }

  // Every remaining /api/mfa endpoint is owner-authorized exclusively from the session cookie.
  const session = getSession(req, "authenticated");
  if (!session || session.ownerId !== ACCOUNT_OWNER_ID || !csrfValid(req, session)) return genericError(req, 403);

  if (url.pathname === "/api/mfa/provision") {
    const secret = generateBase32Secret();
    session.mfaSecret = await encryptSecret(secret);
    session.mfaStatus = "provisioning";
    session.lastTotpCounter = undefined;
    session.totpFailures = 0;
    session.totpLockUntil = 0;
    const currentCode = await totpFor(secret, Math.floor(Date.now() / 30_000));
    const accountLabel = encodeURIComponent("Northstar Bank:Marcus");
    const issuer = encodeURIComponent("Northstar Bank");
    return json(req, {
      ok: true,
      manualSecret: secret,
      provisioningUri: `otpauth://totp/${accountLabel}?secret=${secret}&issuer=${issuer}&period=30&digits=6`,
      mockCurrentCode: currentCode,
    });
  }

  if (url.pathname === "/api/mfa/activate") {
    const now = Date.now();
    if (!session.mfaSecret || session.mfaStatus !== "provisioning") return genericError(req);
    if (session.totpLockUntil > now) return genericError(req, 429);
    if (!validOtp(body.code)) return genericError(req);
    const secret = await decryptSecret(session.mfaSecret);
    const baseCounter = Math.floor(now / 30_000);
    let matchedCounter: number | null = null;
    for (const candidate of [baseCounter - 1, baseCounter, baseCounter + 1]) {
      if (candidate >= 0 && await totpFor(secret, candidate) === body.code) {
        matchedCounter = candidate;
        break;
      }
    }
    if (matchedCounter === null || session.lastTotpCounter === matchedCounter) {
      session.totpFailures++;
      if (session.totpFailures >= 5) session.totpLockUntil = now + LOCKOUT_MS;
      return genericError(req, session.totpLockUntil > now ? 429 : 400);
    }
    session.lastTotpCounter = matchedCounter;
    session.totpFailures = 0;
    const backups = await createBackupCodes();
    session.backupCodes = backups.stored;
    session.mfaStatus = "active";
    return json(req, { ok: true, backupCodes: backups.visible });
  }

  if (url.pathname === "/api/mfa/backup/regenerate") {
    if (session.mfaStatus !== "active") return genericError(req, 400);
    const backups = await createBackupCodes();
    session.backupCodes = backups.stored; // invalidates old set atomically in memory
    return json(req, { ok: true, backupCodes: backups.visible });
  }

  if (url.pathname === "/api/mfa/backup/acknowledge") {
    if (session.mfaStatus !== "active") return genericError(req, 400);
    return json(req, { ok: true });
  }

  if (url.pathname === "/api/mfa/recovery/verify") {
    if (session.mfaStatus !== "active" || typeof body.code !== "string") return genericError(req);
    const code = body.code.trim().toUpperCase();
    if (!/^[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}$/.test(code)) return genericError(req);
    const candidate = await hashValue(code);
    const stored = session.backupCodes.find((item) => !item.used && item.hash === candidate);
    if (!stored) return json(req, { ok: false, message: "That recovery code could not be accepted." }, 400);
    stored.used = true;
    return json(req, { ok: true, message: "Recovery code accepted. It cannot be used again." });
  }

  return genericError(req, 404);
}

const port = Number(Bun.env.PORT || 3000);

// Requirement 3: HTTPS is mandatory. Certificates are intentionally loaded from the required local cert paths.
Bun.serve({
  hostname: "0.0.0.0",
  port,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(req) {
    try {
      return await handle(req);
    } catch {
      // Requirement 2: production-safe generic response, never an exception/stack trace.
      return genericError(req, 500);
    }
  },
});
