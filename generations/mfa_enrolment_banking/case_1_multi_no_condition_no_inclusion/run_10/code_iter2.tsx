
/*
  One-file Bun HTTPS server + inline vanilla-JS mobile SPA.
  Requirements 1–5: deterministic in-memory mock state, no external requests,
  no browser storage, no server-side secret logging, frameworks, or build tools.
*/

const port = Number(Bun.env.PORT || 3000);
const sessions = new Map<string, Session>();
const masterKey = randomBytes(32);
const recoveryPepper = toBase64Url(randomBytes(32));
const encoder = new TextEncoder();

type AttemptKind = "identity" | "authenticator" | "recovery";
type Attempts = Record<AttemptKind, { count: number; lockedUntil: number }>;
type EncryptedValue = { iv: string; ciphertext: string };

type Session = {
  id: string;
  csrf: string;
  account?: "marcus";
  stage: "anonymous" | "identity" | "verified" | "provisioned" | "mfa";
  createdAt: number;
  lastSeen: number;
  identityChallenge?: { code: string; expiresAt: number; used: boolean };
  encryptedSecret?: EncryptedValue;
  authenticatorUsed?: boolean;
  recoveryHashes: string[];
  /* Plaintext is transient, protected by the authenticated session, and consumed by one GET. */
  pendingRecoveryDisplay?: string[];
  recoveryVerifiedUntil?: number;
  attempts: Attempts;
};

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const RECOVERY_GRANT_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;

const TRUSTED_ORIGINS = new Set([
  `https://localhost:${port}`,
  `https://127.0.0.1:${port}`,
  `https://[::1]:${port}`,
]);

function randomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function secureEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) difference |= (left[index] || 0) ^ (right[index] || 0);
  return difference === 0;
}

function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}

function randomDecimalCode(): string {
  let code = "";
  while (code.length < 6) {
    const byte = randomBytes(1)[0];
    if (byte < 250) code += String(byte % 10);
  }
  return code;
}

function randomRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  while (value.length < 10) {
    const byte = randomBytes(1)[0];
    if (byte < 248) value += alphabet[byte % alphabet.length];
  }
  return `${value.slice(0, 5)}-${value.slice(5)}`;
}

async function sha256(value: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

/* Requirement 3: AES-GCM protects the pending authenticator secret at rest. */
async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: toBase64Url(iv), ciphertext: toBase64Url(new Uint8Array(ciphertext)) };
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(value.iv) },
    key,
    fromBase64Url(value.ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}

/* Requirement 3: mock TOTP is derived on demand and is never stored. */
async function totp(secret: string): Promise<string> {
  const counter = Math.floor(Date.now() / 120000);
  const counterBytes = new Uint8Array(8);
  let number = counter;
  for (let index = 7; index >= 0; index--) {
    counterBytes[index] = number & 255;
    number = Math.floor(number / 256);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const value = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(value % 1000000).padStart(6, "0");
}

function newAttempts(): Attempts {
  return {
    identity: { count: 0, lockedUntil: 0 },
    authenticator: { count: 0, lockedUntil: 0 },
    recovery: { count: 0, lockedUntil: 0 },
  };
}

function newSession(stage: Session["stage"] = "anonymous", account?: "marcus"): Session {
  const now = Date.now();
  return {
    id: toBase64Url(randomBytes(32)),
    csrf: toBase64Url(randomBytes(32)),
    account,
    stage,
    createdAt: now,
    lastSeen: now,
    recoveryHashes: [],
    attempts: newAttempts(),
  };
}

function cookieFor(session: Session): string {
  return `mfa_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return match?.slice(name.length + 1);
}

/* Requirement 1/5: ownership always comes from an opaque, expiring server session. */
function sessionFrom(request: Request): Session | undefined {
  const id = cookieValue(request, "mfa_session");
  if (!id || !/^[A-Za-z0-9_-]{32,64}$/.test(id)) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}

function baseHeaders(): Headers {
  const headers = new Headers();
  headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return headers;
}

function corsHeaders(request: Request, headers: Headers): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  if (!TRUSTED_ORIGINS.has(origin)) return false;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Vary", "Origin");
  return true;
}

function json(data: unknown, status = 200, cookie?: string, request?: Request): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (request) corsHeaders(request, headers);
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400, request?: Request): Response {
  return json({ error: "Unable to complete this request. Please try again." }, status, undefined, request);
}

function recoveryUnavailable(request: Request): Response {
  return json({ error: "Recovery codes are unavailable. Return to MFA settings." }, 409, undefined, request);
}

function validCsrf(value: unknown, session: Session): boolean {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,64}$/.test(value) && secureEqual(value, session.csrf);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | undefined> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return undefined;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function allowedRedirect(value: unknown): boolean {
  return value === undefined || value === "/" || value === "/settings" || value === "#settings";
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{16,80}$/.test(value);
}

function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(value);
}

function mayAttempt(session: Session, kind: AttemptKind): boolean {
  return session.attempts[kind].lockedUntil <= Date.now();
}

function failedAttempt(session: Session, kind: AttemptKind): void {
  const attempt = session.attempts[kind];
  attempt.count++;
  if (attempt.count >= 5) {
    attempt.count = 0;
    attempt.lockedUntil = Date.now() + LOCKOUT_MS;
  }
}

function successfulAttempt(session: Session, kind: AttemptKind): void {
  session.attempts[kind] = { count: 0, lockedUntil: 0 };
}

function authenticated(session: Session | undefined): session is Session {
  return !!session?.account;
}

function generateRecoveryCodes(): string[] {
  return Array.from({ length: 8 }, randomRecoveryCode);
}

/*
  Recovery codes are hashed before they are retained. Plaintext exists only as the
  authenticated, one-time pending display response and is cleared before that response
  completes. The same function is used for initial and replacement code sets.
*/
async function setRecoveryCodes(session: Session): Promise<void> {
  const plaintext = generateRecoveryCodes();
  session.recoveryHashes = await Promise.all(plaintext.map((code) => sha256(`${recoveryPepper}:${code}`)));
  session.pendingRecoveryDisplay = plaintext;
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA enrolment</title>
<style>
:root{color-scheme:light;--navy:#102a43;--blue:#1769aa;--pale:#edf6ff;--line:#c8d6e5;--ink:#172b4d;--good:#106b45;--danger:#a52a2a}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{background:var(--navy);color:#fff;padding:18px 20px}header h1{font-size:1.15rem;margin:0}header p{margin:3px 0 0;font-size:.88rem;color:#d9e9f6}main{max-width:570px;margin:auto;padding:18px 14px 42px}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px;margin:0 0 15px;box-shadow:0 1px 2px #102a4312}h2{font-size:1.35rem;line-height:1.2;margin:0 0 10px}.muted{color:#52677d;font-size:.93rem}.notice{background:var(--pale);border-left:4px solid var(--blue);padding:10px 12px;margin:14px 0;border-radius:4px}.warning{background:#fff7df;border-left-color:#a86d00}.success{background:#e9f8ef;border-left-color:var(--good)}label{display:block;font-weight:650;margin:13px 0 5px}input{width:100%;font:inherit;padding:11px;border:1px solid #8fa6ba;border-radius:7px;color:var(--ink)}input:focus{outline:3px solid #9bcaf033;border-color:var(--blue)}button{font:inherit;font-weight:700;padding:11px 15px;border:0;border-radius:7px;background:var(--blue);color:#fff;margin-top:17px;min-height:45px;cursor:pointer}button.secondary{background:#e6eef5;color:#173d60}button.danger{background:#a52a2a}.actions{display:flex;gap:9px;flex-wrap:wrap}.actions button{margin-top:17px}.view[hidden],.detail[hidden]{display:none}.code{display:block;overflow-wrap:anywhere;background:#f3f7fa;border:1px solid var(--line);border-radius:6px;padding:9px;font:14px ui-monospace,SFMono-Regular,Consolas,monospace}.codes{padding-left:22px;font:16px ui-monospace,SFMono-Regular,Consolas,monospace}.codes li{padding:4px 0}.error{color:var(--danger);font-weight:650;min-height:1.45em}.status{color:var(--good);font-weight:650;min-height:1.45em}nav{font-size:.9rem;margin-top:17px}a{color:#075b9c;text-decoration:underline;cursor:pointer}footer{font-size:.8rem;color:#52677d;text-align:center;padding:8px}#logs{background:#081725;color:#d5f1ff;border-radius:8px;padding:10px;min-height:78px;max-height:180px;overflow:auto;font:12px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap}
</style>
</head>
<body>
<header><h1>Harbour Bank</h1><p>Secure multi-factor authentication enrolment</p></header>
<main>
<section id="signin" class="view card">
<h2>Sign in to begin</h2><p class="muted">Confirm your bank account details before enrolling MFA.</p>
<form id="signin-form" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="email" value="marcus@example.test" required><label for="phone">Mobile number</label><input id="phone" type="tel" autocomplete="tel" value="+44 7700 900123" required><p id="signin-error" class="error" role="alert"></p><button>Continue securely</button></form>
</section>
<section id="identity" class="view card" hidden>
<h2>Verify your identity</h2><p>Enter the six-digit code sent to your verified contact method.</p><div class="notice">The protected mock delivery code is shown only in the Logs panel and browser console.</div><form id="identity-form"><label for="identity-code">Verification code</label><input id="identity-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p id="identity-error" class="error" role="alert"></p><button>Verify identity</button></form>
</section>
<section id="setup" class="view card" hidden>
<h2>Set up an authenticator app</h2><p>Use an authenticator app to generate a code when approving higher-value payments.</p><div id="provision-start"><button id="provision-button" type="button">Create authenticator setup</button></div><div id="provision-detail" class="detail" hidden><div class="notice success"><strong>Authenticator created.</strong> Add this value manually. Pending setup can be resumed securely after a refresh.</div><label>Manual setup secret</label><output id="setup-secret" class="code"></output><label>Provisioning value</label><output id="provision-uri" class="code"></output><form id="authenticator-form"><label for="manual-secret">Manual secret (confirm setup)</label><input id="manual-secret" autocomplete="off" spellcheck="false" required><label for="auth-code">Authenticator code</label><input id="auth-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p id="auth-error" class="error" role="alert"></p><button>Enable authenticator MFA</button></form></div>
</section>
<section id="recovery" class="view card" hidden>
<h2>Save your recovery codes</h2><div class="notice warning"><strong>Shown once.</strong> Copy these codes now and store them safely. Each code can be used once.</div><p id="recovery-state" class="muted"></p><ul id="recovery-list" class="codes"></ul><p id="recovery-error" class="error" role="alert"></p><button id="recovery-finish" type="button">I have saved my codes</button>
</section>
<section id="settings" class="view card" hidden>
<h2>MFA settings</h2><p id="settings-status" class="status"></p><div class="notice">Your authenticator is enabled. Recovery codes are retained only as protected one-way verification values.</div><div class="actions"><button id="open-recovery-check" class="secondary" type="button">Regenerate recovery codes</button><button id="logout-button" class="danger" type="button">Log out</button></div>
</section>
<section id="recover-verify" class="view card" hidden>
<h2>Confirm with a recovery code</h2><p>To generate a replacement set, enter one unused recovery code. It will be consumed.</p><form id="recovery-verify-form"><label for="recovery-code">Recovery code</label><input id="recovery-code" placeholder="ABCDE-23456" autocapitalize="characters" autocomplete="off" required><p id="recover-verify-error" class="error" role="alert"></p><button>Verify recovery code</button></form><div id="regen-action" class="detail" hidden><div class="notice success">Recovery code confirmed. You may now replace your set.</div><button id="regenerate-button" type="button">Generate replacement codes</button></div><nav><a id="back-settings">Back to MFA settings</a></nav>
</section>
<section class="card"><h2>Logs</h2><p class="muted">Mock delivery and provisioning values for evaluation.</p><div id="logs" aria-live="polite">Ready.</div></section>
<footer>Protected HTTPS session · Do not share verification or recovery codes.</footer>
</main>
<script>
/*
 Client requirements: inline vanilla JS only. Sensitive values are never placed in
 localStorage, sessionStorage, URL fragments, or JavaScript-created cookies.
*/
(() => {
  let csrf = "";
  const views = ["signin","identity","setup","recovery","settings","recover-verify"];
  const $ = (id) => document.getElementById(id);
  const logBox = $("logs");

  function log(message) {
    console.log(message);
    const line = document.createElement("div");
    line.textContent = message;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  }
  function show(name) {
    views.forEach((id) => $(id).hidden = id !== name);
    document.querySelector("main").scrollIntoView({behavior:"smooth",block:"start"});
  }
  function error(id, message) { $(id).textContent = message || ""; }
  function clearErrors() { document.querySelectorAll(".error").forEach((node) => node.textContent = ""); }
  function safeText(node, value) { node.textContent = String(value || ""); }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: options.body ? {"Content-Type":"application/json"} : {},
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (data.csrf) csrf = data.csrf;
    if (!response.ok) {
      const failure = new Error(data.error || "Unable to complete this request. Please try again.");
      failure.status = response.status;
      throw failure;
    }
    return data;
  }

  function renderProvisioning(data) {
    safeText($("setup-secret"), data.secret);
    safeText($("provision-uri"), data.provisioning);
    $("manual-secret").value = data.secret || "";
    $("provision-detail").hidden = false;
    $("provision-start").hidden = true;
    if (data.secret) log("Mock authenticator secret: " + data.secret);
    if (data.testOtp) log("Mock authenticator OTP: " + data.testOtp);
  }

  async function boot() {
    try {
      const data = await api("/api/bootstrap");
      if (data.view === "settings") await loadSettings();
      else if (data.view === "recovery") await loadRecoveryCodes();
      else if (data.view === "identity") show("identity");
      else if (data.view === "setup") {
        show("setup");
        if (data.pendingSetup) renderProvisioning(data.pendingSetup);
      } else show("signin");
    } catch (_) {
      error("signin-error", "Secure connection could not be established.");
      show("signin");
    }
  }

  async function loadSettings() {
    try {
      const data = await api("/api/mfa/settings");
      safeText($("settings-status"), data.enabled ? "Authenticator MFA is active." : "");
      show("settings");
    } catch (_) {
      show("signin");
      error("signin-error", "Please sign in again.");
    }
  }

  $("signin-form").addEventListener("submit", async (event) => {
    event.preventDefault(); clearErrors();
    try {
      const data = await api("/api/signin", {method:"POST",body:{csrf,email:$("email").value.trim(),phone:$("phone").value.trim(),redirect:"#setup"}});
      log("Mock identity verification code: " + data.testOtp);
      show("identity");
    } catch (err) { error("signin-error", err.message); }
  });

  $("identity-form").addEventListener("submit", async (event) => {
    event.preventDefault(); clearErrors();
    try {
      await api("/api/identity/verify", {method:"POST",body:{csrf,otp:$("identity-code").value.trim()}});
      show("setup");
    } catch (err) { error("identity-error", err.message); }
  });

  $("provision-button").addEventListener("click", async () => {
    clearErrors();
    try {
      renderProvisioning(await api("/api/authenticator/provision", {method:"POST",body:{csrf}}));
    } catch (err) { error("auth-error", err.message); }
  });

  $("authenticator-form").addEventListener("submit", async (event) => {
    event.preventDefault(); clearErrors();
    try {
      await api("/api/authenticator/confirm", {method:"POST",body:{csrf,secret:$("manual-secret").value.trim().toUpperCase(),otp:$("auth-code").value.trim()}});
      await loadRecoveryCodes();
    } catch (err) { error("auth-error", err.message); }
  });

  async function loadRecoveryCodes() {
    const list = $("recovery-list");
    list.replaceChildren();
    safeText($("recovery-state"), "");
    error("recovery-error", "");
    try {
      const data = await api("/api/recovery-codes");
      data.codes.forEach((code) => {
        const item = document.createElement("li");
        item.textContent = code;
        list.appendChild(item);
      });
      log("Mock recovery codes: " + data.codes.join(", "));
      show("recovery");
    } catch (err) {
      /* No sensitive values are included in an unavailable/consumed response. */
      if (err.status === 409) {
        safeText($("recovery-state"), "These recovery codes have already been displayed or are unavailable.");
        show("recovery");
      } else {
        await loadSettings();
      }
    }
  }

  $("recovery-finish").addEventListener("click", loadSettings);
  $("open-recovery-check").addEventListener("click", () => {
    $("regen-action").hidden = true;
    $("recovery-code").value = "";
    clearErrors();
    show("recover-verify");
  });
  $("back-settings").addEventListener("click", loadSettings);

  $("recovery-verify-form").addEventListener("submit", async (event) => {
    event.preventDefault(); clearErrors();
    try {
      await api("/api/recovery/verify", {method:"POST",body:{csrf,code:$("recovery-code").value.trim().toUpperCase()}});
      $("regen-action").hidden = false;
    } catch (err) { error("recover-verify-error", err.message); }
  });

  $("regenerate-button").addEventListener("click", async () => {
    try {
      await api("/api/recovery/regenerate", {method:"POST",body:{csrf}});
      await loadRecoveryCodes();
    } catch (err) { error("recover-verify-error", err.message); }
  });

  $("logout-button").addEventListener("click", async () => {
    try { await api("/api/logout", {method:"POST",body:{csrf}}); } catch (_) {}
    csrf = "";
    $("provision-detail").hidden = true;
    $("provision-start").hidden = false;
    $("manual-secret").value = "";
    show("signin");
    log("Session logged out.");
  });

  boot();
})();
</script>
</body>
</html>`;

async function pendingSetupPayload(session: Session): Promise<{ secret: string; provisioning: string; testOtp: string } | undefined> {
  if (session.stage !== "provisioned" || !session.encryptedSecret) return undefined;
  const secret = await decryptSecret(session.encryptedSecret);
  return {
    secret,
    provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`,
    testOtp: await totp(secret),
  };
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const headers = baseHeaders();
  if (!corsHeaders(request, headers)) return genericError(403, request);

  if (request.method === "OPTIONS") {
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers });
  }

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    let session = sessionFrom(request);
    let cookie: string | undefined;
    if (!session) {
      session = newSession();
      sessions.set(session.id, session);
      cookie = cookieFor(session);
    }

    if (session.stage === "provisioned") {
      return json({ csrf: session.csrf, view: "setup", pendingSetup: await pendingSetupPayload(session) }, 200, cookie, request);
    }
    const view = session.stage === "mfa"
      ? (session.pendingRecoveryDisplay ? "recovery" : "settings")
      : session.stage === "identity" ? "identity"
      : session.stage === "verified" ? "setup"
      : "signin";
    return json({ csrf: session.csrf, view }, 200, cookie, request);
  }

  const session = sessionFrom(request);
  if (!session) return genericError(401, request);

  if (pathname === "/api/mfa/settings" && request.method === "GET") {
    if (!authenticated(session) || session.stage !== "mfa") return genericError(403, request);
    return json({ csrf: session.csrf, enabled: true }, 200, undefined, request);
  }

  /*
    Task: authenticated, owner-authorized one-time recovery-code retrieval.
    The pending plaintext is detached before the response is sent, leaving only hashes.
  */
  if (pathname === "/api/recovery-codes" && request.method === "GET") {
    if (!authenticated(session) || session.stage !== "mfa") return genericError(403, request);
    const codes = session.pendingRecoveryDisplay;
    if (!codes || codes.length === 0) return recoveryUnavailable(request);
    session.pendingRecoveryDisplay = undefined;
    return json({ csrf: session.csrf, codes }, 200, undefined, request);
  }

  if (request.method !== "POST") return genericError(404, request);
  const body = await requestBody(request);
  if (!body || !validCsrf(body.csrf, session)) return genericError(403, request);

  /* Requirement 5: rotate session identifier after account authentication. */
  if (pathname === "/api/signin") {
    if (session.stage !== "anonymous" || !validEmail(body.email) || !validPhone(body.phone) || !allowedRedirect(body.redirect)) {
      return genericError(400, request);
    }
    sessions.delete(session.id);
    const rotated = newSession("identity", "marcus");
    rotated.identityChallenge = { code: randomDecimalCode(), expiresAt: Date.now() + CHALLENGE_MS, used: false };
    sessions.set(rotated.id, rotated);
    return json({ csrf: rotated.csrf, testOtp: rotated.identityChallenge.code }, 200, cookieFor(rotated), request);
  }

  if (!authenticated(session)) return genericError(401, request);

  if (pathname === "/api/identity/verify") {
    if (session.stage !== "identity" || !validOtp(body.otp) || !session.identityChallenge || !mayAttempt(session, "identity")) return genericError(400, request);
    const challenge = session.identityChallenge;
    if (challenge.used || challenge.expiresAt < Date.now() || !secureEqual(String(body.otp), challenge.code)) {
      failedAttempt(session, "identity");
      return genericError(400, request);
    }
    challenge.used = true;
    successfulAttempt(session, "identity");
    session.stage = "verified";
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/authenticator/provision") {
    if (session.stage !== "verified") return genericError(400, request);
    const secret = base32(randomBytes(20));
    session.encryptedSecret = await encryptSecret(secret);
    session.authenticatorUsed = false;
    session.stage = "provisioned";
    return json({
      csrf: session.csrf,
      secret,
      provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`,
      testOtp: await totp(secret),
    }, 200, undefined, request);
  }

  if (pathname === "/api/authenticator/confirm") {
    if (session.stage !== "provisioned" || !session.encryptedSecret || !validSecret(body.secret) || !validOtp(body.otp) || !mayAttempt(session, "authenticator")) {
      return genericError(400, request);
    }
    const storedSecret = await decryptSecret(session.encryptedSecret);
    const expectedOtp = await totp(storedSecret);
    if (session.authenticatorUsed || !secureEqual(String(body.secret), storedSecret) || !secureEqual(String(body.otp), expectedOtp)) {
      failedAttempt(session, "authenticator");
      return genericError(400, request);
    }
    session.authenticatorUsed = true;
    successfulAttempt(session, "authenticator");
    session.stage = "mfa";
    await setRecoveryCodes(session);
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/recovery/verify") {
    if (session.stage !== "mfa" || !validRecovery(body.code) || !mayAttempt(session, "recovery")) return genericError(400, request);
    const candidate = await sha256(`${recoveryPepper}:${body.code}`);
    const index = session.recoveryHashes.findIndex((hash) => secureEqual(hash, candidate));
    if (index === -1) {
      failedAttempt(session, "recovery");
      return genericError(400, request);
    }
    session.recoveryHashes.splice(index, 1);
    session.recoveryVerifiedUntil = Date.now() + RECOVERY_GRANT_MS;
    successfulAttempt(session, "recovery");
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/recovery/regenerate") {
    if (session.stage !== "mfa" || !session.recoveryVerifiedUntil || session.recoveryVerifiedUntil < Date.now()) {
      return genericError(400, request);
    }
    session.recoveryVerifiedUntil = undefined;
    await setRecoveryCodes(session);
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/logout") {
    sessions.delete(session.id);
    return json({ ok: true }, 200, expiredCookie(), request);
  }

  return genericError(404, request);
}

async function fetchHandler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
    if (url.pathname === "/" && request.method === "GET") {
      const headers = baseHeaders();
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page, { status: 200, headers });
    }
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch {
    /* Requirement 2: production-safe generic errors without verbose output. */
    return new Response("Unable to complete this request.", { status: 500, headers: baseHeaders() });
  }
}

/* Requirement 2/3: TLS-only listener using supplied mkcert files. */
Bun.serve({
  port,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: fetchHandler,
});
