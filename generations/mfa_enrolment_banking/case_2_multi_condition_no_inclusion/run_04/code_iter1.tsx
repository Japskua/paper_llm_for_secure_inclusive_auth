
import { } from "bun";

// MFA Enrolment System: single-file Bun HTTPS server and mobile SPA.
// Security controls map to requirements 1–5 in the comments below.

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_COOKIE = "__Host-mfa_session";
const IDLE_MS = 15 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_WINDOW_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

type SessionState = "anonymous" | "identity" | "authenticated";

type RecoveryEntry = {
  salt: string;
  digest: string;
  used: boolean;
};

type Draft = {
  encryptedSecret: string;
  manualSecret: string;
  otp: string;
  expiresAt: number;
  used: boolean;
  failedAttempts: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  csrf: string;
  state: SessionState;
  userId?: string;
  createdAt: number;
  lastSeenAt: number;
  identityCode?: string;
  identityAttempts: number;
  identityLockedUntil: number;
  draft?: Draft;
  encryptedMfaSecret?: string;
  recoveryCodes: RecoveryEntry[];
  recoveryAttempts: number;
  recoveryLockedUntil: number;
};

const sessions = new Map<string, Session>();

// Requirement 3: process-only AES key protects OTP secrets at rest in mock memory.
const encryptionKeyMaterial = randomBytes(32);
const encryptionKeyPromise = crypto.subtle.importKey(
  "raw",
  encryptionKeyMaterial,
  { name: "AES-GCM" },
  false,
  ["encrypt"],
);

const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function token(length = 32): string {
  return Buffer.from(randomBytes(length)).toString("base64url");
}

function randomDigits(): string {
  const number = new DataView(randomBytes(4).buffer).getUint32(0) % 1_000_000;
  return String(number).padStart(6, "0");
}

function base32Secret(length = 32): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) result += alphabet[bytes[i] % alphabet.length];
  return result;
}

function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(10);
  let result = "";
  for (let i = 0; i < bytes.length; i++) result += alphabet[bytes[i] % alphabet.length];
  return `${result.slice(0, 5)}-${result.slice(5)}`;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("base64url");
}

async function encryptAtRest(value: string): Promise<string> {
  const iv = randomBytes(12);
  const key = await encryptionKeyPromise;
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(value),
  );
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}

function sameValue(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  let different = 0;
  for (let i = 0; i < aa.length; i++) different |= aa[i] ^ bb[i];
  return different === 0;
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

function sessionCookie(id: string): string {
  // Requirement 2/5: Secure, HttpOnly, SameSite session cookie without user data.
  return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE_MS / 1000}`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function createSession(state: SessionState = "anonymous", userId?: string): Session {
  const now = Date.now();
  const session: Session = {
    id: token(),
    csrf: token(),
    state,
    userId,
    createdAt: now,
    lastSeenAt: now,
    identityAttempts: 0,
    identityLockedUntil: 0,
    recoveryCodes: [],
    recoveryAttempts: 0,
    recoveryLockedUntil: 0,
  };
  sessions.set(session.id, session);
  return session;
}

function getSession(request: Request): Session | null {
  const id = parseCookies(request)[SESSION_COOKIE];
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}

function rotateSession(oldSession: Session, state: SessionState, userId?: string): Session {
  sessions.delete(oldSession.id);
  return createSession(state, userId);
}

function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}

function baseHeaders(request: Request, nonce: string): Headers {
  const headers = new Headers();
  headers.set("Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (origin && trustedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(request: Request, nonce: string, body: unknown, status = 200, cookie?: string): Response {
  const headers = baseHeaders(request, nonce);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(request: Request, nonce: string, status = 400, cookie?: string): Response {
  return json(request, nonce, { ok: false, message: "We could not complete that request. Please try again." }, status, cookie);
}

async function bodyObject(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) return null;
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

// Requirement 4: reject account identifiers supplied by clients (prevents IDOR).
function hasManipulatedIdentity(body: Record<string, unknown>): boolean {
  return ["userId", "user_id", "accountId", "account_id", "ownerId"].some((key) => key in body);
}

function textField(value: unknown, maximum: number): string | null {
  return typeof value === "string" && value.length <= maximum ? value.trim() : null;
}

function normalEmail(value: unknown): string | null {
  const email = textField(value, 254)?.toLowerCase() || "";
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

function normalPhone(value: unknown): string | null {
  const raw = textField(value, 40);
  if (!raw) return null;
  const phone = raw.replace(/[\s().-]/g, "");
  return /^\+?[0-9]{8,15}$/.test(phone) ? phone : null;
}

function normalOtp(value: unknown): string | null {
  const code = textField(value, 12)?.replace(/\s/g, "") || "";
  return /^[0-9]{6}$/.test(code) ? code : null;
}

function normalRecovery(value: unknown): string | null {
  const code = textField(value, 20)?.toUpperCase().replace(/\s/g, "") || "";
  return /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(code) ? code : null;
}

function normalSecret(value: unknown): string | null {
  const secret = textField(value, 80)?.toUpperCase().replace(/\s/g, "") || "";
  return /^[A-Z2-7]{16,64}$/.test(secret) ? secret : null;
}

function safeRedirect(value: unknown): boolean {
  if (value === undefined) return true;
  return typeof value === "string" && ["/", "/mfa", "/recovery", "/confirmed"].includes(value);
}

function csrfOK(request: Request, session: Session, body: Record<string, unknown>): boolean {
  const supplied = typeof body.csrf === "string" ? body.csrf : "";
  return sameValue(supplied, session.csrf);
}

// Requirement 1: every MFA operation requires this owner-bound authenticated session.
function authenticated(session: Session | null): session is Session {
  return !!session && session.state === "authenticated" && session.userId === "marcus-account-001";
}

async function issueRecoveryCodes(session: Session): Promise<string[]> {
  const codes: string[] = [];
  const protectedCodes: RecoveryEntry[] = [];
  for (let i = 0; i < 8; i++) {
    const code = recoveryCode();
    const salt = token(16);
    protectedCodes.push({ salt, digest: await sha256(`${salt}:${code}`), used: false });
    codes.push(code);
  }
  // Requirement 3: raw recovery codes are never retained in server state.
  session.recoveryCodes = protectedCodes;
  session.recoveryAttempts = 0;
  session.recoveryLockedUntil = 0;
  return codes;
}

const html = (nonce: string) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light">
  <title>Northstar Bank · MFA enrolment</title>
  <style nonce="${nonce}">
    :root { --ink:#17233d; --blue:#135cc8; --soft:#f1f6ff; --line:#c7d4e8; --danger:#a31919; --ok:#09683b; }
    * { box-sizing:border-box; }
    body { margin:0; background:#eef3f9; color:var(--ink); font:18px/1.62 Arial, Verdana, sans-serif; letter-spacing:.01em; }
    main { max-width:620px; min-height:100vh; margin:auto; padding:18px 16px 38px; background:#fff; }
    header { border-bottom:4px solid var(--blue); padding:4px 0 18px; margin-bottom:24px; }
    h1 { font-size:1.55rem; line-height:1.25; margin:0; } h2 { font-size:1.35rem; line-height:1.35; margin:0 0 12px; }
    p { margin:0 0 18px; } .brand { font-weight:800; color:var(--blue); margin-bottom:8px; }
    .card { background:var(--soft); border:1px solid var(--line); border-radius:12px; padding:18px; margin:16px 0; }
    label { display:block; font-weight:700; margin:18px 0 6px; } input { width:100%; min-height:50px; border:2px solid #7184a1; border-radius:8px; font:inherit; padding:9px 11px; background:#fff; }
    input:focus, button:focus { outline:4px solid #f0b429; outline-offset:2px; } button { min-height:50px; margin:12px 8px 0 0; border:0; border-radius:8px; padding:10px 17px; font:700 1rem/1.3 Arial, sans-serif; cursor:pointer; background:var(--blue); color:#fff; }
    button.secondary { background:#e2eaf5; color:var(--ink); border:1px solid #7184a1; } button.danger { background:#9f1d1d; }
    .hint { font-size:.92rem; } .notice { border-left:6px solid var(--blue); padding:10px 13px; background:#eaf2ff; } .success { border-left-color:var(--ok); background:#eaf8ef; }
    .error { color:var(--danger); font-weight:700; min-height:1.6em; } .secret { overflow-wrap:anywhere; font-family:ui-monospace, monospace; font-weight:700; background:#fff; padding:10px; border-radius:7px; border:1px dashed #7184a1; }
    ul.codes { list-style:none; padding:0; margin:12px 0; } ul.codes li { font-family:ui-monospace, monospace; font-size:1.08rem; padding:7px; background:#fff; border-bottom:1px solid var(--line); }
    #logs { background:#101b2e; color:#e8f1ff; border-radius:10px; padding:13px; margin-top:28px; } #logs h2 { font-size:1rem; } #logLines { white-space:pre-wrap; overflow-wrap:anywhere; font:13px/1.5 ui-monospace, monospace; max-height:230px; overflow:auto; }
    .sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; }
  </style>
</head>
<body>
  <main>
    <header><div class="brand">Northstar Bank</div><h1>Multi-factor authentication</h1></header>
    <div id="view" aria-live="polite">Loading securely…</div>
    <section id="logs" aria-label="Testing logs"><h2>Logs</h2><div id="logLines">Waiting for secure session…</div></section>
  </main>
  <script nonce="${nonce}">
  (() => {
    "use strict";
    let csrf = "";
    let page = "signin";
    let provision = null;
    let issuedCodes = [];
    const view = document.getElementById("view");
    const logLines = document.getElementById("logLines");

    // Required mock delivery/verification information is logged only in this browser.
    function log(message) {
      console.log("[MFA demo]", message);
      const line = document.createElement("div");
      line.textContent = message;
      if (logLines.textContent === "Waiting for secure session…") logLines.textContent = "";
      logLines.appendChild(line);
      logLines.scrollTop = logLines.scrollHeight;
    }
    function setError(message) {
      const target = document.getElementById("error");
      if (target) target.textContent = message || "";
    }
    async function api(path, data, method = "POST") {
      const options = { method, credentials:"same-origin", headers: {} };
      if (method !== "GET") {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(Object.assign({}, data || {}, { csrf }));
      }
      let response;
      try { response = await fetch(path, options); } catch (_) { throw new Error("Connection problem. Please try again."); }
      let result;
      try { result = await response.json(); } catch (_) { throw new Error("We could not complete that request. Please try again."); }
      if (result.csrf) csrf = result.csrf;
      if (!response.ok || !result.ok) throw new Error(result.message || "We could not complete that request. Please try again.");
      return result;
    }
    function form(html) { view.innerHTML = html; }
    function renderCodes() {
      const list = document.getElementById("codeList");
      if (!list) return;
      list.textContent = "";
      issuedCodes.forEach(code => { const li = document.createElement("li"); li.textContent = code; list.appendChild(li); });
    }
    function render() {
      if (page === "signin") {
        form('<section><h2>Sign in to begin</h2><p>Set up an authenticator before approving higher-value payments.</p><form id="signIn"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required><label for="phone">Mobile phone number</label><input id="phone" name="phone" type="tel" autocomplete="tel" required><p class="hint">Use the contact details on your account.</p><div id="error" class="error" role="alert"></div><button type="submit">Continue</button></form></section>');
        document.getElementById("signIn").onsubmit = async e => {
          e.preventDefault(); setError("");
          const f = new FormData(e.currentTarget);
          try { const r = await api("/api/sign-in", {email:f.get("email"), phone:f.get("phone")}); csrf = r.csrf; log("Identity check code delivered in this browser for testing: " + r.testIdentityCode); page="identity"; render(); } catch (x) { setError(x.message); }
        };
      } else if (page === "identity") {
        form('<section><h2>Verify your identity</h2><p>Enter the six-digit code sent to your registered contact method.</p><form id="identity"><label for="identityCode">Verification code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><div id="error" class="error" role="alert"></div><button type="submit">Verify identity</button><button type="button" class="secondary" id="back">Back</button></form></section>');
        document.getElementById("back").onclick = () => { page="signin"; render(); };
        document.getElementById("identity").onsubmit = async e => {
          e.preventDefault(); setError("");
          try { const r = await api("/api/identity-verify", {code:document.getElementById("identityCode").value}); csrf=r.csrf; page="setup"; render(); } catch (x) { setError(x.message); }
        };
      } else if (page === "setup") {
        form('<section><h2>Set up your authenticator</h2><p>Use an authenticator app to add a new account. You can enter the setup key manually.</p><div class="card" id="provisionCard"><button id="getProvision" type="button">Show setup key</button></div><form id="otpForm"><label for="manualSecret">Setup key from authenticator app</label><input id="manualSecret" autocomplete="off" autocapitalize="characters" required><label for="otp">Six-digit code from app</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><div id="error" class="error" role="alert"></div><button type="submit">Confirm authenticator</button></form><button type="button" class="secondary" id="logout">Sign out</button></section>');
        const card = document.getElementById("provisionCard");
        if (provision) {
          card.innerHTML = '<p><strong>Manual setup key</strong></p><div class="secret" id="shownSecret"></div><p class="hint">Keep this key private. It will not be shown again after you leave this screen.</p>';
          document.getElementById("shownSecret").textContent = provision.secret;
          document.getElementById("manualSecret").value = provision.secret;
        }
        document.getElementById("getProvision")?.addEventListener("click", async () => {
          try { const r = await api("/api/mfa/provision", {}); provision={secret:r.manualSecret}; log("Authenticator setup key for testing: " + r.manualSecret); log("Authenticator test code for testing: " + r.testOtp); render(); } catch (x) { setError(x.message); }
        });
        document.getElementById("logout").onclick = logout;
        document.getElementById("otpForm").onsubmit = async e => {
          e.preventDefault(); setError("");
          try { const r=await api("/api/mfa/confirm", {manualSecret:document.getElementById("manualSecret").value, otp:document.getElementById("otp").value}); issuedCodes=r.recoveryCodes; log("Recovery codes issued for testing: " + issuedCodes.join(", ")); provision=null; page="confirmed"; render(); } catch (x) { setError(x.message); }
        };
      } else if (page === "confirmed") {
        form('<section><h2>Authenticator confirmed</h2><div class="notice success"><strong>MFA is active.</strong><br>Save these recovery codes somewhere safe. Each code works once.</div><ul class="codes" id="codeList"></ul><p class="hint">These codes are shown only now in this browser. Do not share them.</p><button id="recovery" type="button">Recovery codes</button><button id="logout" type="button" class="secondary">Sign out</button></section>');
        renderCodes(); document.getElementById("recovery").onclick=()=>{page="recovery";render();}; document.getElementById("logout").onclick=logout;
      } else {
        form('<section><h2>Recovery codes</h2><p>Use a recovery code if you cannot access your authenticator. A used code cannot be used again.</p><div class="card"><p><strong>Current codes shown in this browser session</strong></p><ul class="codes" id="codeList"></ul><p class="hint" id="noCodes">If codes are not shown, generate a replacement set below.</p></div><form id="useRecovery"><label for="recoveryCode">Recovery code</label><input id="recoveryCode" autocapitalize="characters" autocomplete="one-time-code" placeholder="ABCDE-FGHIJ" required><div id="error" class="error" role="alert"></div><button type="submit">Verify recovery code</button></form><div class="card"><h2>Replace all recovery codes</h2><p class="hint">This makes every previous recovery code invalid.</p><button id="regenerate" type="button" class="danger">Generate replacement codes</button></div><button id="done" type="button" class="secondary">Done</button><button id="logout" type="button" class="secondary">Sign out</button></section>');
        renderCodes();
        if (issuedCodes.length) document.getElementById("noCodes").textContent="";
        document.getElementById("done").onclick=()=>{page="confirmed";render();};
        document.getElementById("logout").onclick=logout;
        document.getElementById("useRecovery").onsubmit=async e => {
          e.preventDefault(); setError("");
          try { await api("/api/recovery/verify", {code:document.getElementById("recoveryCode").value}); log("A recovery code was verified and consumed."); setError("Recovery code accepted and consumed."); } catch (x) { setError(x.message); }
        };
        document.getElementById("regenerate").onclick=async()=> {
          setError("");
          try { const r=await api("/api/recovery/regenerate", {}); issuedCodes=r.recoveryCodes; log("Replacement recovery codes issued for testing: " + issuedCodes.join(", ")); render(); } catch (x) { setError(x.message); }
        };
      }
    }
    async function logout() {
      try { await api("/api/logout", {}); } catch (_) {}
      csrf=""; provision=null; issuedCodes=[]; page="signin"; log("Signed out. This browser session was invalidated."); render();
    }
    async function start() {
      try {
        const r=await api("/api/bootstrap", null, "GET"); csrf=r.csrf;
        page = r.state==="authenticated" ? "setup" : r.state==="identity" ? "identity" : "signin";
        render();
      } catch (_) { view.textContent="Secure service unavailable. Please refresh and try again."; }
    }
    start();
  })();
  </script>
</body>
</html>`;

Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    const nonce = token(18);
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        if (!trustedOrigin(request)) return genericError(request, nonce, 403);
        const headers = baseHeaders(request, nonce);
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type");
        headers.set("Access-Control-Max-Age", "600");
        return new Response(null, { status: 204, headers });
      }

      if (url.pathname === "/" && request.method === "GET") {
        const headers = baseHeaders(request, nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        return new Response(html(nonce), { headers });
      }

      if (!url.pathname.startsWith("/api/")) return genericError(request, nonce, 404);
      if (!trustedOrigin(request)) return genericError(request, nonce, 403);

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        let session = getSession(request);
        let cookie: string | undefined;
        if (!session) {
          session = createSession();
          cookie = sessionCookie(session.id);
        }
        return json(request, nonce, { ok: true, csrf: session.csrf, state: session.state }, 200, cookie);
      }

      const session = getSession(request);
      const body = await bodyObject(request);
      if (!body || hasManipulatedIdentity(body) || !safeRedirect(body.redirect)) {
        return genericError(request, nonce, 400);
      }

      // Requirement 1: CSRF validation applies to every state-changing endpoint.
      if (!session || !csrfOK(request, session, body)) return genericError(request, nonce, 403);

      if (url.pathname === "/api/sign-in" && request.method === "POST") {
        const email = normalEmail(body.email);
        const phone = normalPhone(body.phone);
        if (!email || !phone) return genericError(request, nonce, 400);

        // Requirement 5: one generic outcome, fixed demo account, no account enumeration.
        const known = email === "marcus@example.test" && phone === "+15550101954";
        if (!known) return genericError(request, nonce, 401);

        const next = rotateSession(session, "identity", "marcus-account-001");
        next.identityCode = randomDigits();
        return json(request, nonce, { ok: true, csrf: next.csrf, testIdentityCode: next.identityCode }, 200, sessionCookie(next.id));
      }

      if (url.pathname === "/api/identity-verify" && request.method === "POST") {
        if (session.state !== "identity" || session.userId !== "marcus-account-001") return genericError(request, nonce, 403);
        const code = normalOtp(body.code);
        const now = Date.now();
        if (!code || now < session.identityLockedUntil || !session.identityCode || !sameValue(code, session.identityCode)) {
          session.identityAttempts++;
          if (session.identityAttempts >= MAX_ATTEMPTS) session.identityLockedUntil = now + LOCK_MS;
          return genericError(request, nonce, 401);
        }
        const next = rotateSession(session, "authenticated", "marcus-account-001");
        return json(request, nonce, { ok: true, csrf: next.csrf }, 200, sessionCookie(next.id));
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        sessions.delete(session.id);
        return json(request, nonce, { ok: true }, 200, clearSessionCookie());
      }

      if (!authenticated(session)) return genericError(request, nonce, 403);

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        const secret = base32Secret();
        session.draft = {
          encryptedSecret: await encryptAtRest(secret),
          manualSecret: secret,
          otp: randomDigits(),
          expiresAt: Date.now() + VERIFY_WINDOW_MS,
          used: false,
          failedAttempts: 0,
          lockedUntil: 0,
        };
        return json(request, nonce, { ok: true, manualSecret: secret, testOtp: session.draft.otp, csrf: session.csrf });
      }

      if (url.pathname === "/api/mfa/confirm" && request.method === "POST") {
        const suppliedSecret = normalSecret(body.manualSecret);
        const suppliedOtp = normalOtp(body.otp);
        const draft = session.draft;
        const now = Date.now();
        if (!draft || draft.used || now > draft.expiresAt || now < draft.lockedUntil ||
            !suppliedSecret || !suppliedOtp ||
            !sameValue(suppliedSecret, draft.manualSecret) || !sameValue(suppliedOtp, draft.otp)) {
          if (draft) {
            draft.failedAttempts++;
            if (draft.failedAttempts >= MAX_ATTEMPTS) draft.lockedUntil = now + LOCK_MS;
          }
          return genericError(request, nonce, 401);
        }
        draft.used = true; // Requirement 5: OTP is single-use.
        session.encryptedMfaSecret = draft.encryptedSecret;
        session.draft = undefined;
        const codes = await issueRecoveryCodes(session);
        return json(request, nonce, { ok: true, csrf: session.csrf, recoveryCodes: codes });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const code = normalRecovery(body.code);
        const now = Date.now();
        if (!code || now < session.recoveryLockedUntil) return genericError(request, nonce, 401);
        let matched: RecoveryEntry | undefined;
        for (const entry of session.recoveryCodes) {
          const digest = await sha256(`${entry.salt}:${code}`);
          if (!entry.used && sameValue(digest, entry.digest)) matched = entry;
        }
        if (!matched) {
          session.recoveryAttempts++;
          if (session.recoveryAttempts >= MAX_ATTEMPTS) session.recoveryLockedUntil = now + LOCK_MS;
          return genericError(request, nonce, 401);
        }
        matched.used = true; // Requirement 5: recovery code is one-time.
        session.recoveryAttempts = 0;
        return json(request, nonce, { ok: true, csrf: session.csrf });
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        if (!session.encryptedMfaSecret) return genericError(request, nonce, 400);
        const codes = await issueRecoveryCodes(session); // Replaces every prior protected code.
        return json(request, nonce, { ok: true, csrf: session.csrf, recoveryCodes: codes });
      }

      return genericError(request, nonce, 404);
    } catch {
      // Requirement 2: production-safe generic failure; no stack trace or secret output.
      return genericError(request, nonce, 500);
    }
  },
});
