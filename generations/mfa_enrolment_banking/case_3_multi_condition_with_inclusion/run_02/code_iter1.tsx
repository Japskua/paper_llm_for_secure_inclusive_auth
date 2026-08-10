
/*
 MFA Enrolment System
 Requirements 1: MFA API routes use the authenticated session user only and CSRF checks.
 Requirements 2: secure headers, strict cookies, restricted CORS, generic server errors.
 Requirements 3: TLS when certificates are present; cryptographic random values; encrypted/hashed memory state.
 Requirements 4: validated inputs; no user IDs, secrets, or redirects accepted from clients.
 Requirements 5: expiring single-use mock OTPs, failed-attempt lockout, rotating expiring sessions.
*/

const encoder = new TextEncoder();

type Session = {
  userId: string;
  csrf: string;
  created: number;
  lastSeen: number;
};

type MfaState = {
  encryptedSecret?: string;
  provisionedAt?: number;
  verified: boolean;
  backupHashes: string[];
  usedOtps: Set<string>;
  failedAttempts: number;
  lockedUntil: number;
};

const sessions = new Map<string, Session>();
const mfaStates = new Map<string, MfaState>();

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const OTP_VALID_MS = 10 * 60_000;
const LOCKOUT_MS = 5 * 60_000;
const TRUSTED_ORIGIN = "https://localhost:3000";
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function sixDigitCode(): string {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
}

function recoveryCodes(): string[] {
  return Array.from({ length: 8 }, () => {
    const raw = randomToken(9).replace(/[-_]/g, "X").toUpperCase();
    return raw.slice(0, 5) + "-" + raw.slice(5, 10) + "-" + raw.slice(10, 15);
  });
}

async function hashValue(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(hash).toString("base64url");
}

async function encryptAtRest(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(ciphertext).toString("base64url");
}

function secureCookie(name: string, value: string, maxAge?: number): string {
  const age = maxAge === undefined ? "" : `; Max-Age=${maxAge}`;
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function securityHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Access-Control-Allow-Origin": TRUSTED_ORIGIN,
    "Vary": "Origin",
    ...extra,
  };
}

function apiResponse(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({ "Content-Type": "application/json; charset=utf-8", ...extra }),
  });
}

function cookieValue(request: Request, name: string): string | undefined {
  const match = (request.headers.get("cookie") || "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(name + "="));
  return match?.slice(name.length + 1);
}

function requireSession(request: Request): { id: string; session: Session } | null {
  const id = cookieValue(request, "sid");
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();

  if (!id || !session || now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }

  session.lastSeen = now;
  return { id, session };
}

function csrfIsValid(request: Request, session: Session): boolean {
  return request.headers.get("x-csrf-token") === session.csrf;
}

async function requestBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function getState(userId: string): MfaState {
  let state = mfaStates.get(userId);
  if (!state) {
    state = {
      verified: false,
      backupHashes: [],
      usedOtps: new Set(),
      failedAttempts: 0,
      lockedUntil: 0,
    };
    mfaStates.set(userId, state);
  }
  return state;
}

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank MFA</title>
<style>
  :root {
    font-family: Verdana, Arial, sans-serif;
    color: #14213d;
    background: #f3f7fb;
    letter-spacing: .035em;
    line-height: 1.7;
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; }
  .wrap { max-width: 540px; margin: 0 auto; padding: 18px; }
  .brand { color: #174c88; font-size: .95rem; font-weight: bold; margin: 4px 0 14px; }
  .card, .logs-card {
    background: #fff;
    border-radius: 16px;
    padding: 23px;
    box-shadow: 0 2px 13px rgba(20, 33, 61, .10);
  }
  .logs-card { margin-top: 16px; }
  h1 { font-size: 1.55rem; line-height: 1.32; margin: 0 0 10px; }
  h2 { font-size: 1.08rem; line-height: 1.4; margin: 0 0 8px; }
  p { margin: 10px 0; }
  .step { color: #315b96; font-weight: bold; margin: 0 0 4px; }
  .icon { font-size: 2rem; line-height: 1.2; margin-bottom: 8px; }
  label { display: block; font-weight: bold; margin-top: 15px; }
  small { display: block; font-size: .88rem; font-weight: normal; color: #39495e; letter-spacing: .02em; }
  input {
    width: 100%;
    min-height: 51px;
    margin-top: 5px;
    border: 2px solid #62748b;
    border-radius: 9px;
    padding: 10px 12px;
    color: #14213d;
    font: inherit;
    font-size: 1rem;
    background: white;
  }
  input.code-input { letter-spacing: .18em; font-size: 1.2rem; }
  button {
    width: 100%;
    min-height: 51px;
    margin-top: 17px;
    padding: 11px 14px;
    cursor: pointer;
    border: 0;
    border-radius: 9px;
    background: #075bb5;
    color: white;
    font: inherit;
    font-weight: bold;
    letter-spacing: .025em;
  }
  button.secondary {
    margin-top: 10px;
    background: white;
    border: 2px solid #075bb5;
    color: #075bb5;
  }
  button:focus, input:focus, a:focus { outline: 3px solid #e49b24; outline-offset: 2px; }
  .hint, .notice, .error {
    margin-top: 17px;
    padding: 12px;
    border-radius: 9px;
  }
  .hint { background: #edf4ff; }
  .notice { background: #e7f7ed; }
  .error { background: #ffe9e9; color: #761b1b; }
  .secret, .codes {
    overflow-wrap: anywhere;
    background: #f1f5f9;
    border-radius: 9px;
    padding: 13px;
    font-family: Verdana, Arial, sans-serif;
    letter-spacing: .07em;
  }
  .codes { line-height: 2; }
  .qr-wrap {
    display: flex;
    justify-content: center;
    margin: 15px 0 7px;
  }
  .qr {
    width: 180px;
    height: 180px;
    border: 10px solid white;
    background: white;
    image-rendering: pixelated;
  }
  .logs {
    max-height: 180px;
    overflow: auto;
    margin: 9px 0 0;
    padding: 10px;
    border-radius: 8px;
    background: #11243d;
    color: #e7f2ff;
    font-family: monospace;
    font-size: .76rem;
    letter-spacing: 0;
    line-height: 1.55;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .muted { color: #48566a; }
  @media (max-width: 390px) {
    .wrap { padding: 12px; }
    .card, .logs-card { padding: 18px; }
    h1 { font-size: 1.38rem; }
  }
</style>
</head>
<body>
<main class="wrap">
  <p class="brand">SecureBank · account protection</p>
  <section class="card" id="app" aria-live="polite"></section>
  <section class="logs-card" aria-label="Simulation logs">
    <h2>Logs</h2>
    <p class="muted">Safe test messages from this browser.</p>
    <pre class="logs" id="logs">Ready.</pre>
  </section>
</main>
<script>
/*
 Inclusivity: each screen has one prominent action, plain short instructions,
 no moving content or reading deadline, examples, retry options, and copy support.
 Client state is only held in JavaScript memory: no localStorage, sessionStorage, or client cookies.
*/
(function () {
  var csrf = "";
  var setupSecret = "";
  var setupUri = "";
  var app = document.getElementById("app");
  var logPanel = document.getElementById("logs");

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (character) {
      return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character];
    });
  }

  function addLog(message) {
    console.log(message);
    logPanel.textContent += "\\n" + message;
    logPanel.scrollTop = logPanel.scrollHeight;
  }

  async function api(path, method, data) {
    var response = await fetch(path, {
      method: method || "GET",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: data === undefined ? undefined : JSON.stringify(data)
    });
    var payload;
    try { payload = await response.json(); }
    catch (_) { throw new Error("Something went wrong. Please try again."); }
    if (!response.ok) throw new Error(payload.error || "Something went wrong. Please try again.");
    return payload;
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        showMessage("Copied. You can paste it where you need it.");
      }).catch(function () {
        showMessage("Please select the text and copy it.");
      });
    } else {
      showMessage("Please select the text and copy it.");
    }
  }

  function showMessage(message) {
    var existing = document.getElementById("copy-message");
    if (existing) existing.textContent = message;
  }

  function help() {
    return '<aside class="hint"><strong>💡 Need help?</strong><br>You can retry safely. There is no reading deadline.</aside>';
  }

  function qrSvg(value) {
    var bits = [];
    for (var i = 0; i < value.length; i++) {
      var n = value.charCodeAt(i);
      for (var bit = 0; bit < 8; bit++) bits.push((n >> bit) & 1);
    }
    var cells = "";
    var size = 21;
    function finder(x, y) {
      for (var row = 0; row < 7; row++) {
        for (var col = 0; col < 7; col++) {
          var edge = row === 0 || row === 6 || col === 0 || col === 6;
          var middle = row >= 2 && row <= 4 && col >= 2 && col <= 4;
          if (edge || middle) cells += '<rect x="' + (x + col) + '" y="' + (y + row) + '" width="1" height="1"/>';
        }
      }
    }
    finder(0, 0); finder(14, 0); finder(0, 14);
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        var inFinder = (x < 8 && y < 8) || (x > 12 && y < 8) || (x < 8 && y > 12);
        if (!inFinder && bits[(x * 11 + y * 7) % bits.length]) {
          cells += '<rect x="' + x + '" y="' + y + '" width="1" height="1"/>';
        }
      }
    }
    return '<svg class="qr" viewBox="0 0 21 21" role="img" aria-label="Setup QR code"><rect width="21" height="21" fill="white"/><g fill="#14213d">' + cells + '</g></svg>';
  }

  function showError(message, retry) {
    app.innerHTML =
      '<div class="icon">⚠️</div><h1>Please check that</h1>' +
      '<p class="error">' + escapeHtml(message) + '</p>' +
      '<button id="retry">Try again</button>' + help();
    document.getElementById("retry").onclick = retry || showSetup;
  }

  function showLogin() {
    app.innerHTML =
      '<p class="step">Step 1 of 4</p><div class="icon">🔐</div>' +
      '<h1>Set up extra sign-in protection</h1>' +
      '<p>We will help you add an authenticator and save recovery codes.</p>' +
      '<label for="email">Email <small>Example: marcus@example.com</small></label>' +
      '<input id="email" type="email" autocomplete="email" inputmode="email" value="marcus@example.com">' +
      '<button id="continue">Continue</button>' + help();

    document.getElementById("continue").onclick = async function () {
      try {
        var email = document.getElementById("email").value;
        var result = await api("/api/login", "POST", { email: email });
        csrf = result.csrf;
        addLog("Mock sign-in confirmed. Starting MFA enrolment.");
        showSetup();
      } catch (error) {
        showError(error.message, showLogin);
      }
    };
  }

  async function showSetup() {
    app.innerHTML =
      '<p class="step">Step 2 of 4</p><div class="icon">📱</div>' +
      '<h1>Add your authenticator</h1>' +
      '<p>Scan the QR code with your authenticator app. Or copy the setup key and paste it into the app.</p>' +
      '<div class="qr-wrap" id="qr-holder"></div>' +
      '<p class="secret" id="secret-value">Getting your setup key…</p>' +
      '<button class="secondary" id="copy-secret">Copy setup key</button>' +
      '<button class="secondary" id="copy-uri">Copy setup link</button>' +
      '<p id="copy-message" class="muted" aria-live="polite"></p>' +
      '<label for="otp">Enter the 6-digit code from your app <small>Example: 123456</small></label>' +
      '<input class="code-input" id="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6">' +
      '<button id="verify">Verify code</button>' + help();

    try {
      var result = await api("/api/mfa/provision", "POST", {});
      setupSecret = result.secret;
      setupUri = result.provisioningUri;
      document.getElementById("secret-value").textContent = setupSecret;
      document.getElementById("qr-holder").innerHTML = qrSvg(setupUri);
      addLog("Mock authenticator setup key: " + setupSecret);
      addLog("Mock test verification code: " + result.mockOtp);
    } catch (error) {
      showError(error.message, showSetup);
      return;
    }

    document.getElementById("copy-secret").onclick = function () { copyText(setupSecret); };
    document.getElementById("copy-uri").onclick = function () { copyText(setupUri); };
    document.getElementById("verify").onclick = async function () {
      try {
        var otp = document.getElementById("otp").value;
        await api("/api/mfa/verify", "POST", { otp: otp });
        addLog("Mock authenticator code verified.");
        showRecoveryCodes();
      } catch (error) {
        showError(error.message, showSetup);
      }
    };
  }

  async function showRecoveryCodes() {
    try {
      var result = await api("/api/mfa/backup-codes", "POST", {});
      var codes = result.codes;
      addLog("Mock backup recovery codes: " + codes.join(", "));

      app.innerHTML =
        '<p class="step">Step 3 of 4</p><div class="icon">🧾</div>' +
        '<h1>Save your recovery codes</h1>' +
        '<p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p>' +
        '<div class="codes">' + codes.map(escapeHtml).join("<br>") + '</div>' +
        '<button class="secondary" id="copy-codes">Copy recovery codes</button>' +
        '<p id="copy-message" class="muted" aria-live="polite"></p>' +
        '<button id="finish">I have saved them</button>' + help();

      document.getElementById("copy-codes").onclick = function () { copyText(codes.join("\\n")); };
      document.getElementById("finish").onclick = showComplete;
    } catch (error) {
      showError(error.message, showSetup);
    }
  }

  function showComplete() {
    app.innerHTML =
      '<p class="step">Step 4 of 4</p><div class="icon">✅</div>' +
      '<h1>MFA is ready</h1>' +
      '<p>Your authenticator is set up and your recovery codes have been shown.</p>' +
      '<p class="notice"><strong>What happens next:</strong><br>Use your authenticator when asked to confirm a payment.</p>' +
      '<button id="signout">Sign out</button>';
    document.getElementById("signout").onclick = async function () {
      try { await api("/api/logout", "POST", {}); } catch (_) {}
      csrf = "";
      setupSecret = "";
      setupUri = "";
      addLog("Signed out. Session removed.");
      showLogin();
    };
  }

  showLogin();
}());
</script>
</body>
</html>`;
}

const certificate = Bun.file("certs/cert.pem");
const privateKey = Bun.file("certs/key.pem");
const hasTlsCertificates = await certificate.exists() && await privateKey.exists();

const server = Bun.serve({
  port: 3000,
  ...(hasTlsCertificates ? { tls: { cert: certificate, key: privateKey } } : {}),
  fetch: async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: securityHeaders({
          "Access-Control-Allow-Methods": "GET, POST",
          "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
        }),
      });
    }

    if (request.method === "GET" && path === "/") {
      return new Response(pageHtml(), {
        headers: securityHeaders({ "Content-Type": "text/html; charset=utf-8" }),
      });
    }

    if (request.method === "POST" && path === "/api/login") {
      const input = await requestBody(request);
      const email = typeof input.email === "string" ? input.email.trim() : "";

      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return apiResponse({ error: "Enter an email in the example format: name@example.com." }, 400);
      }

      // Requirement 5: fresh random identifier prevents session fixation.
      const sid = randomToken();
      const csrf = randomToken();
      sessions.set(sid, {
        userId: "marcus-account",
        csrf,
        created: Date.now(),
        lastSeen: Date.now(),
      });

      return apiResponse(
        { csrf },
        200,
        { "Set-Cookie": secureCookie("sid", sid, Math.floor(SESSION_ABSOLUTE_MS / 1000)) },
      );
    }

    const authenticated = requireSession(request);
    if (!authenticated) {
      return apiResponse(
        { error: "Your session ended. Please sign in again." },
        401,
        { "Set-Cookie": secureCookie("sid", "", 0) },
      );
    }

    if (request.method !== "GET" && !csrfIsValid(request, authenticated.session)) {
      return apiResponse({ error: "Your secure form token was missing. Please try again." }, 403);
    }

    // Requirement 1: client input never selects a user; state is always session-bound.
    const state = getState(authenticated.session.userId);

    if (request.method === "POST" && path === "/api/mfa/provision") {
      const secret = randomToken(20);
      state.encryptedSecret = await encryptAtRest(secret);
      state.provisionedAt = Date.now();
      state.verified = false;
      state.usedOtps.clear();

      // This is an intentionally deterministic mock code solely for academic UI testing.
      const mockOtp = "123456";
      const provisioningUri = "otpauth://totp/SecureBank:marcus-account?secret=" +
        encodeURIComponent(secret) + "&issuer=SecureBank&algorithm=SHA1&digits=6&period=30";

      return apiResponse({ secret, provisioningUri, mockOtp });
    }

    if (request.method === "POST" && path === "/api/mfa/verify") {
      const input = await requestBody(request);
      const otp = typeof input.otp === "string" ? input.otp.trim() : "";
      const now = Date.now();

      if (now < state.lockedUntil) {
        return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
      }

      const expired = !state.provisionedAt || now - state.provisionedAt > OTP_VALID_MS;
      const invalid = !/^\d{6}$/.test(otp) || otp !== "123456" || !state.encryptedSecret || expired || state.usedOtps.has(otp);

      if (invalid) {
        state.failedAttempts += 1;
        if (state.failedAttempts >= 5) {
          state.failedAttempts = 0;
          state.lockedUntil = now + LOCKOUT_MS;
        }
        const message = expired
          ? "This setup code has expired. Select Try again to get a new setup key."
          : "That code did not work. Enter the 6 digits from your authenticator, for example 123456.";
        return apiResponse({ error: message }, 400);
      }

      state.usedOtps.add(otp);
      state.failedAttempts = 0;
      state.verified = true;
      return apiResponse({ ok: true });
    }

    if (request.method === "POST" && path === "/api/mfa/backup-codes") {
      if (!state.encryptedSecret || !state.verified) {
        return apiResponse({ error: "Verify your authenticator code before creating recovery codes." }, 400);
      }

      const codes = recoveryCodes();
      state.backupHashes = await Promise.all(codes.map(hashValue));
      return apiResponse({ codes });
    }

    if (request.method === "POST" && path === "/api/logout") {
      sessions.delete(authenticated.id);
      return apiResponse(
        { ok: true },
        200,
        { "Set-Cookie": secureCookie("sid", "", 0) },
      );
    }

    return apiResponse({ error: "Page not found." }, 404);
  },
  error() {
    return new Response("Something went wrong. Please try again.", {
      status: 500,
      headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
    });
  },
});

console.log(`Secure MFA app running at ${hasTlsCertificates ? "https" : "http"}://localhost:${server.port}`);
