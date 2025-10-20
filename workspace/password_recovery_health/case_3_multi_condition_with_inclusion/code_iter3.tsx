
/**
 * app.ts - Single-file HTTPS Bun server + SPA client
 * Run with: bun app.ts  (Bun 1.3.0)
 *
 * Password Recovery System per requirements.
 * - HTTPS with mkcert certs
 * - Strict security headers (HSTS, CSP script-src 'self', etc.)
 * - In-memory stores for users, sessions, tokens, MFA, rate limits
 * - CSRF protection with per-session token
 * - Password reset wizard with verification link/code + MFA
 * - Login with throttling and MFA
 * - SPA with accessible, low-distraction UI, Help panel, persistent progress
 * - All deliveries (reset link, codes) are console.log'd and mirrored to on-page Logs.
 */

// ==============================
// Utility and Security Helpers
// ==============================

// Server secret for signing; new per process. In production, persist securely.
const SERVER_SECRET = crypto.getRandomValues(new Uint8Array(32));

// Time helpers
const now = () => Date.now();

// Base64url encode helper
function base64url(bytes: Uint8Array): string {
  let str = Buffer.from(bytes).toString("base64");
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// Random ID
function randId(bytes = 16): string {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(b);
}

// Hash helpers
async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return Buffer.from(digest).toString("hex");
}

async function hmacSha256Hex(keyBytes: Uint8Array, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return Buffer.from(sig).toString("hex");
}

// Short code derivation (legacy alnum) - kept but not used for MFA/verification anymore
function shortCodeFromHex(hex: string, length = 6): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; code.length < length && i < hex.length; i += 2) {
    const num = parseInt(hex.slice(i, i + 2), 16);
    code += alphabet[num % alphabet.length];
  }
  return code;
}

// Numeric-only 6-digit code from hex (for MFA and reset short codes)
function numericCodeFromHex(hex: string, length = 6): string {
  let code = "";
  for (let i = 0; code.length < length && i < hex.length; i += 2) {
    const num = parseInt(hex.slice(i, i + 2), 16);
    code += String(num % 10);
  }
  // pad if needed
  while (code.length < length) code += "0";
  return code.slice(0, length);
}

// Mask email for privacy
function maskEmail(email: string): string {
  const [user, domain] = email.split("@");
  if (!domain) return "account";
  const [name, tld] = domain.split(".");
  const u = user ? user[0] + "*".repeat(Math.max(0, user.length - 1)) : "*";
  const n = name ? name[0] + "*".repeat(Math.max(0, name.length - 1)) : "*";
  const t = tld ? tld : "";
  return `${u}@${n}${t ? "." + t : ""}`;
}

// Escape HTML to prevent XSS in any dynamic UI strings (server side utility)
function escapeHtml(s: string): string {
  return s.replace(/[&<>'"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c] as string));
}

// ==============================
// In-memory Stores (non-persistent)
// ==============================

type User = {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
};
const usersByEmail = new Map<string, User>();
const usersById = new Map<string, User>();

// Seed demo user with bcrypt via Bun.password.hash
const DEMO_EMAIL = "helena.patient@examplehospital.org";
let DEMO_USER_ID = randId(12);
let DEMO_USER: User;
const demoHash = await Bun.password.hash("StrongP@ssw0rd!2025", {
  algorithm: "bcrypt",
  cost: 10,
});
DEMO_USER = {
  id: DEMO_USER_ID,
  email: DEMO_EMAIL,
  passwordHash: demoHash,
  mfaEnabled: true,
};
usersByEmail.set(DEMO_EMAIL.toLowerCase(), DEMO_USER);
usersById.set(DEMO_USER_ID, DEMO_USER);

type ResetContext = { userId: string; token: string; mfaVerified?: boolean; createdAt: number };
type Session = {
  id: string;
  csrf: string;
  userId?: string;
  pendingLoginUserId?: string;
  createdAt: number;
  lastSeen: number;
  counters: Record<string, number>;
  reset?: ResetContext;
};
const sessions = new Map<string, Session>();

type ResetTokenRecord = {
  token: string;
  userId: string;
  createdAt: number;
  used: boolean;
  shortCode: string;
  attempts: number;
  mfaAttempts: number;
  decoy?: boolean;
};
const resetTokens = new Map<string, ResetTokenRecord>();
const resetCodes = new Map<string, string>(); // shortCode -> token

// MFA codes (demo)
const mfaForReset = new Map<string, string>(); // token -> mfa code (numeric 6)
const mfaForLogin = new Map<string, string>(); // userId -> mfa code (numeric 6)

// Rate limits
type RateEntry = { count: number; first: number };
const rateLimits = new Map<string, RateEntry>();
function rateKey(ip: string, scope: string) {
  return `${ip}:${scope}`;
}
function checkRate(ip: string, scope: string, limit: number, windowMs: number): { ok: boolean; retryAfter?: number } {
  const key = rateKey(ip, scope);
  const nowMs = now();
  const entry = rateLimits.get(key);
  if (!entry) {
    rateLimits.set(key, { count: 1, first: nowMs });
    return { ok: true };
  }
  if (nowMs - entry.first > windowMs) {
    rateLimits.set(key, { count: 1, first: nowMs });
    return { ok: true };
  }
  entry.count += 1;
  if (entry.count > limit) {
    const retryAfter = Math.ceil((entry.first + windowMs - nowMs) / 1000);
    return { ok: false, retryAfter };
  }
  return { ok: true };
}

// ==============================
// Cookies and Session Management
// ==============================

function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.get("cookie") || "";
  const out: Record<string, string> = {};
  header.split(";").forEach(part => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("="));
  });
  return out;
}

async function signSessionId(id: string): Promise<string> {
  const sig = await hmacSha256Hex(SERVER_SECRET, id);
  return `${id}.${sig}`;
}

async function verifySessionCookie(cookieVal: string): Promise<string | null> {
  const idx = cookieVal.lastIndexOf(".");
  if (idx === -1) return null;
  const id = cookieVal.slice(0, idx);
  const sig = cookieVal.slice(idx + 1);
  const expect = await hmacSha256Hex(SERVER_SECRET, id);
  if (sig === expect) return id;
  return null;
}

async function getOrCreateSession(req: Request): Promise<{ session: Session; setCookie?: string }> {
  const cookies = parseCookies(req);
  const cookieVal = cookies["sid"];
  if (cookieVal) {
    const id = await verifySessionCookie(cookieVal);
    if (id) {
      const s = sessions.get(id);
      if (s) {
        s.lastSeen = now();
        return { session: s };
      }
    }
  }
  const id = randId(18);
  const csrf = randId(18);
  const session: Session = { id, csrf, createdAt: now(), lastSeen: now(), counters: {} };
  sessions.set(id, session);
  const signed = await signSessionId(id);
  const setCookie = `sid=${signed}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${60 * 60 * 24 * 7}`;
  return { session, setCookie };
}

// ==============================
// Security Headers per response
// ==============================

function securityHeaders(): Headers {
  const h = new Headers();
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  h.set("Cache-Control", "no-store");

  const baseCsp = [
    "default-src 'none'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "font-src 'self'",
    "script-src 'self'",
  ];
  h.set("Content-Security-Policy", baseCsp.join("; "));
  return h;
}

// ==============================
// CSRF Validation
// ==============================

async function requireCsrf(req: Request, session: Session): Promise<Response | null> {
  const token = req.headers.get("x-csrf-token") || "";
  if (!token || token !== session.csrf) {
    const h = securityHeaders();
    h.set("Content-Type", "application/json");
    return new Response(JSON.stringify({ ok: false, error: "CSRF validation failed" }), { status: 403, headers: h });
  }
  return null;
}

// ==============================
// Password Policy
// ==============================

const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "qwerty", "qwerty123", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
]);

function validatePasswordPolicy(pw: string): { ok: boolean; message?: string } {
  if (pw.length < 12) return { ok: false, message: "Password must be at least 12 characters." };
  if (!/[a-z]/.test(pw)) return { ok: false, message: "Include a lowercase letter." };
  if (!/[A-Z]/.test(pw)) return { ok: false, message: "Include an uppercase letter." };
  if (!/[0-9]/.test(pw)) return { ok: false, message: "Include a number." };
  if (!/[^\w\s]/.test(pw)) return { ok: false, message: "Include a special character." };
  if (COMMON_PASSWORDS.has(pw.toLowerCase())) return { ok: false, message: "Password is too common." };
  return { ok: true };
}

// ==============================
// MFA generation (deterministic demo) - numeric 6 digits
// ==============================

async function deriveMfaForReset(token: string): Promise<string> {
  const hex = await sha256Hex(`reset:${token}:mfa`);
  return numericCodeFromHex(hex, 6);
}
async function deriveMfaForLogin(userId: string): Promise<string> {
  const hex = await sha256Hex(`login:${userId}:${Buffer.from(SERVER_SECRET).toString("hex")}`);
  return numericCodeFromHex(hex, 6);
}

// ==============================
// HTML SPA Template (no inline scripts)
// ==============================

function spaHtml(csrf: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Healthcare Account — Secure Login & Password Recovery</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${escapeHtml(csrf)}">
  <style>
    /* Inclusivity: low-distraction, readable typography, clear structure */
    :root {
      --bg: #f7f9fb;
      --card: #ffffff;
      --text: #1e2a3a;
      --muted: #5a6b7b;
      --primary: #2f6fed;
      --accent: #19b394;
      --danger: #d93f4c;
      --warning: #e6a700;
      --border: #e1e7ef;
      --focus: #ffbf47;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      line-height: 1.5;
    }
    header {
      background: var(--card); border-bottom: 1px solid var(--border);
      position: sticky; top: 0; z-index: 10;
    }
    .container { max-width: 980px; margin: 0 auto; padding: 16px; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand .logo {
      width: 36px; height: 36px; border-radius: 8px; background: linear-gradient(135deg,var(--primary),var(--accent)); display: inline-block;
    }
    .title { font-size: 1.1rem; font-weight: 700; }
    main { padding: 16px; }
    .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
    @media (min-width: 900px) { .grid { grid-template-columns: 2fr 1fr; } }

    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
    h1, h2, h3 { margin: 0 0 8px 0; }
    p { margin: 0 0 8px; color: var(--muted); }
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; }
    .tab { background: #eef3fb; border: 1px solid var(--border); padding: 8px 12px; border-radius: 8px; cursor: pointer; }
    .tab[aria-selected="true"] { background: #dbe8ff; border-color: var(--primary); }
    .progress {
      display: flex; gap: 8px; margin: 8px 0 16px;
    }
    .step {
      flex: 1; height: 8px; background: #eef2f7; border-radius: 4px; position: relative; overflow: hidden;
    }
    .step::after {
      content: ""; position: absolute; inset: 0; background: var(--accent); width: 0%;
    }
    .step.done::after { width: 100%; }
    .step.current::after { width: 60%; animation: pulse 1.5s ease-in-out infinite alternate; }
    @keyframes pulse { from { width: 40%; } to { width: 80%; } }

    label { display: block; font-weight: 600; margin: 8px 0 4px; }
    input, button, select {
      width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 16px; background: #fff; color: #fff;
      color: var(--text);
    }
    input:focus, button:focus { outline: 3px solid var(--focus); outline-offset: 2px; }
    button.primary { background: var(--primary); color: #fff; border-color: var(--primary); cursor: pointer; }
    button.secondary { background: #eef3fb; border-color: #d1dbf0; }
    button.link { background: transparent; border: none; color: var(--primary); text-decoration: underline; padding: 0; width: auto; }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    .hint { font-size: 0.95rem; color: var(--muted); }
    .danger { color: #d93f4c; }
    .success { color: var(--accent); }
    .warning { color: var(--warning); }
    .hidden { display: none !important; }

    .help-panel { position: sticky; top: 88px; }
    .help-panel details { border: 1px solid var(--border); border-radius: 12px; padding: 12px; background: #f6fbff; }
    .help-panel summary { cursor: pointer; font-weight: 700; }
    .help-panel ul { margin: 8px 0 0 18px; }

    .logs { height: 220px; overflow: auto; background: #0b1021; color: #d5e3ff; font-family: ui-monospace, Menlo, Consolas, monospace; border-radius: 8px; padding: 8px; }
    .note { background: #fff7e6; border: 1px solid #ffe2a8; border-radius: 8px; padding: 8px; }

    .sr-only { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); border: 0; }
  </style>
</head>
<body>
  <header>
    <div class="container brand" role="banner" aria-label="Healthcare secure access">
      <span class="logo" aria-hidden="true"></span>
      <div class="title">Healthcare Account Portal</div>
      <div style="margin-left:auto">
        <button id="helpToggle" class="link" aria-controls="helpArea" aria-expanded="false">Help & Safety</button>
      </div>
    </div>
  </header>
  <main class="container grid" id="root">
    <section class="card">
      <h1 id="flowTitle">Welcome</h1>
      <p id="flowSubtitle">Log in or reset your password in a few clear steps. No time pressure.</p>

      <div class="tabs" role="tablist" aria-label="Authentication options">
        <button role="tab" id="tab-login" class="tab" aria-selected="true" aria-controls="panel-login">Login</button>
        <button role="tab" id="tab-reset" class="tab" aria-selected="false" aria-controls="panel-reset">Reset password</button>
      </div>

      <!-- Login Panel -->
      <section id="panel-login" role="tabpanel" aria-labelledby="tab-login">
        <div class="progress" aria-hidden="true">
          <div class="step" id="loginStep1"></div>
          <div class="step" id="loginStep2"></div>
        </div>

        <div id="loginForm">
          <label for="loginEmail">Email</label>
          <input id="loginEmail" type="email" autocomplete="username" inputmode="email" placeholder="you@example.org" required>
          <label for="loginPassword">Password</label>
          <input id="loginPassword" type="password" autocomplete="current-password" placeholder="••••••••••••" required>
          <div class="row">
            <button id="btnLogin" class="primary">Log in</button>
            <button id="btnLoginForgot" class="secondary">Forgot password</button>
          </div>
          <p class="hint">We will never email you asking for your password. If unsure, use the Reset password tab.</p>
        </div>

        <div id="loginMfa" class="hidden">
          <p>We sent a sign-in code to your trusted device. For this demo, the code is written into the Logs panel.</p>
          <label for="loginMfaCode">Enter 6-digit code</label>
          <input id="loginMfaCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Enter 6-digit code">
          <div class="row">
            <button id="btnLoginMfa" class="primary">Verify and continue</button>
            <button id="btnLoginBack" class="secondary">Back</button>
          </div>
        </div>

        <div id="loginSuccess" class="hidden">
          <h3>Welcome back</h3>
          <p class="success">You are logged in. Please review and accept the updated privacy statement.</p>
          <div class="note">
            <p><strong>Updated privacy statement</strong></p>
            <p>To continue with your appointment booking, please accept our updated privacy terms.</p>
            <div class="row">
              <button id="btnAcceptPrivacy" class="primary">Accept</button>
              <button id="btnLogout" class="secondary">Logout</button>
            </div>
          </div>
        </div>
      </section>

      <!-- Reset Panel -->
      <section id="panel-reset" role="tabpanel" class="hidden" aria-labelledby="tab-reset">
        <div class="progress" aria-hidden="true">
          <div class="step" id="resetStep1"></div>
          <div class="step" id="resetStep2"></div>
          <div class="step" id="resetStep3"></div>
          <div class="step" id="resetStep4"></div>
        </div>

        <div id="resetStepEmail">
          <h2>Step 1: Find your account</h2>
          <p>Enter your email. We'll send a secure reset link and a short code. You can use either.</p>
          <label for="resetEmail">Email</label>
          <input id="resetEmail" type="email" inputmode="email" autocomplete="username" placeholder="you@example.org">
          <div class="row">
            <button id="btnResetRequest" class="primary">Send reset instructions</button>
            <button id="btnResetToLogin" class="secondary">Back to login</button>
          </div>
          <p id="resetEmailMsg" class="hint"></p>
        </div>

        <div id="resetStepVerify" class="hidden">
          <h2>Step 2: Verify it's you</h2>
          <p>Open the link we sent, or enter the short code below. For this demo, check the Logs panel for the link and code.</p>
          <label for="resetCode">Short code</label>
          <input id="resetCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Enter 6-digit code">
          <div class="row">
            <button id="btnVerifyCode" class="primary">Verify code</button>
            <button id="btnPasteLink" class="secondary">Verify from link</button>
          </div>
          <p id="verifyMsg" class="hint"></p>
        </div>

        <div id="resetStepMfa" class="hidden">
          <h2>Step 3: Extra security</h2>
          <p>Enter the 6-digit code. For this demo, the code is printed to Logs.</p>
          <label for="resetMfa">MFA code</label>
          <input id="resetMfa" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Enter 6-digit code">
          <div class="row">
            <button id="btnResetMfa" class="primary">Continue</button>
            <button id="btnResetBackV" class="secondary">Back</button>
          </div>
          <p id="mfaMsg" class="hint"></p>
        </div>

        <div id="resetStepPassword" class="hidden">
          <h2>Step 4: Choose a new password</h2>
          <ul class="hint">
            <li>At least 12 characters</li>
            <li>Include upper and lowercase letters</li>
            <li>Include a number and a special character</li>
            <li>Avoid common passwords</li>
          </ul>
          <label for="newPassword">New password</label>
          <input id="newPassword" type="password" autocomplete="new-password" placeholder="New strong password">
          <label for="newPassword2">Confirm new password</label>
          <input id="newPassword2" type="password" autocomplete="new-password" placeholder="Repeat password">
          <div class="row">
            <button id="btnUpdatePassword" class="primary">Update password</button>
            <button id="btnResetBackMfa" class="secondary">Back</button>
          </div>
          <p id="pwMsg" class="hint"></p>
        </div>

        <div id="resetDone" class="hidden">
          <h2>All set</h2>
          <p class="success">Your password has been changed. For your security, previous sessions are signed out.</p>
          <button id="btnGoLogin" class="primary">Go to login</button>
        </div>
      </section>
    </section>

    <aside id="helpArea" class="help-panel card" aria-live="polite">
      <details>
        <summary>Help & Safety tips</summary>
        <ul>
          <li>Stay on this page (https) and do not share codes or passwords with anyone.</li>
          <li>We will never ask for your password by email or phone.</li>
          <li>If you feel overwhelmed, you can pause. Your progress is saved on this device.</li>
          <li>Use a unique, strong password. Avoid using the same password elsewhere.</li>
          <li>Questions? Contact hospital support by phone; do not click unknown links.</li>
        </ul>
      </details>
      <h3 style="margin-top:12px;">Logs</h3>
      <div class="logs" id="logs" aria-live="polite" aria-label="System logs"></div>
    </aside>
  </main>

  <script src="/app.js" defer></script>
</body>
</html>`;
}

// ==============================
// Client JS (served at /app.js)
// ==============================

function clientJs(): string {
  return `
// Client-side SPA logic
(function() {
  "use strict";

  // CSRF token for all POST requests (Security 1)
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrf = csrfMeta ? csrfMeta.getAttribute('content') || '' : '';

  // Mirror console.log to on-page logs panel (Deliverables)
  const logsEl = document.getElementById('logs');
  const originalLog = console.log.bind(console);
  console.log = (...args) => {
    originalLog(...args);
    const msg = args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
    const div = document.createElement('div');
    div.textContent = msg;
    if (logsEl) {
      logsEl.appendChild(div);
      logsEl.scrollTop = logsEl.scrollHeight;
    }
  };

  function api(path, data) {
    return fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify(data || {})
    }).then(async res => {
      const json = await res.json().catch(() => ({}));
      if (json && Array.isArray(json.log)) {
        json.log.forEach(l => console.log(l));
      }
      if (!res.ok) {
        const err = new Error(json.error || "Request failed");
        err['status'] = res.status;
        throw err;
      }
      return json;
    });
  }

  // State persistence to support pausing (Inclusivity)
  const store = {
    load() { try { return JSON.parse(localStorage.getItem("wizard") || "{}"); } catch { return {}; } },
    save(s) { localStorage.setItem("wizard", JSON.stringify(s)); }
  };
  let state = Object.assign({ flow: "login", loginStep: 1, resetStep: 1, email: "" }, store.load());

  // Elements
  const tabLogin = document.getElementById('tab-login');
  const tabReset = document.getElementById('tab-reset');
  const panelLogin = document.getElementById('panel-login');
  const panelReset = document.getElementById('panel-reset');
  const flowTitle = document.getElementById('flowTitle');
  const flowSubtitle = document.getElementById('flowSubtitle');

  // Login elements
  const loginEmail = document.getElementById('loginEmail');
  const loginPassword = document.getElementById('loginPassword');
  const btnLogin = document.getElementById('btnLogin');
  const btnLoginForgot = document.getElementById('btnLoginForgot');
  const loginForm = document.getElementById('loginForm');
  const loginMfa = document.getElementById('loginMfa');
  const loginSuccess = document.getElementById('loginSuccess');
  const loginStep1 = document.getElementById('loginStep1');
  const loginStep2 = document.getElementById('loginStep2');
  const loginMfaCode = document.getElementById('loginMfaCode');
  const btnLoginMfa = document.getElementById('btnLoginMfa');
  const btnLoginBack = document.getElementById('btnLoginBack');
  const btnAcceptPrivacy = document.getElementById('btnAcceptPrivacy');
  const btnLogout = document.getElementById('btnLogout');

  // Reset elements
  const resetStep1El = document.getElementById('resetStepEmail');
  const resetStep2El = document.getElementById('resetStepVerify');
  const resetStep3El = document.getElementById('resetStepMfa');
  const resetStep4El = document.getElementById('resetStepPassword');
  const resetDoneEl = document.getElementById('resetDone');
  const resetStep1 = document.getElementById('resetStep1');
  const resetStep2 = document.getElementById('resetStep2');
  const resetStep3 = document.getElementById('resetStep3');
  const resetStep4 = document.getElementById('resetStep4');

  const resetEmail = document.getElementById('resetEmail');
  const resetEmailMsg = document.getElementById('resetEmailMsg');
  const btnResetRequest = document.getElementById('btnResetRequest');
  const btnResetToLogin = document.getElementById('btnResetToLogin');

  const resetCode = document.getElementById('resetCode');
  const verifyMsg = document.getElementById('verifyMsg');
  const btnVerifyCode = document.getElementById('btnVerifyCode');
  const btnPasteLink = document.getElementById('btnPasteLink');

  const resetMfa = document.getElementById('resetMfa');
  const mfaMsg = document.getElementById('mfaMsg');
  const btnResetMfa = document.getElementById('btnResetMfa');
  const btnResetBackV = document.getElementById('btnResetBackV');

  const newPassword = document.getElementById('newPassword');
  const newPassword2 = document.getElementById('newPassword2');
  const pwMsg = document.getElementById('pwMsg');
  const btnUpdatePassword = document.getElementById('btnUpdatePassword');
  const btnResetBackMfa = document.getElementById('btnResetBackMfa');
  const btnGoLogin = document.getElementById('btnGoLogin');

  const helpToggle = document.getElementById('helpToggle');
  const helpArea = document.getElementById('helpArea');

  function setTab(flow) {
    state.flow = flow;
    if (tabLogin) tabLogin.setAttribute('aria-selected', flow === 'login' ? 'true' : 'false');
    if (tabReset) tabReset.setAttribute('aria-selected', flow === 'reset' ? 'true' : 'false');
    if (panelLogin) panelLogin.classList.toggle('hidden', flow !== 'login');
    if (panelReset) panelReset.classList.toggle('hidden', flow !== 'reset');
    if (flowTitle) flowTitle.textContent = flow === 'login' ? 'Login' : 'Reset your password';
    if (flowSubtitle) flowSubtitle.textContent = flow === 'login'
      ? 'Enter your details. If you need help, you can switch to password reset.'
      : 'Follow the steps below. You can pause anytime and continue later.';
    render();
    store.save(state);
  }

  function render() {
    if (loginStep1) loginStep1.className = 'step ' + (state.loginStep >= 1 ? (state.loginStep > 1 ? 'done' : 'current') : '');
    if (loginStep2) loginStep2.className = 'step ' + (state.loginStep > 1 ? 'done' : '');

    if (resetStep1) resetStep1.className = 'step ' + (state.resetStep == 1 ? 'current' : (state.resetStep > 1 ? 'done' : ''));
    if (resetStep2) resetStep2.className = 'step ' + (state.resetStep == 2 ? 'current' : (state.resetStep > 2 ? 'done' : ''));
    if (resetStep3) resetStep3.className = 'step ' + (state.resetStep == 3 ? 'current' : (state.resetStep > 3 ? 'done' : ''));
    if (resetStep4) resetStep4.className = 'step ' + (state.resetStep == 4 ? 'current' : (state.resetStep > 4 ? 'done' : ''));

    if (loginForm) loginForm.classList.toggle('hidden', !(state.flow === 'login' && state.loginStep === 1));
    if (loginMfa) loginMfa.classList.toggle('hidden', !(state.flow === 'login' && state.loginStep === 2));
    if (loginSuccess) loginSuccess.classList.toggle('hidden', !(state.flow === 'login' && state.loginStep === 3));

    if (resetStep1El) resetStep1El.classList.toggle('hidden', !(state.flow === 'reset' && state.resetStep === 1));
    if (resetStep2El) resetStep2El.classList.toggle('hidden', !(state.flow === 'reset' && state.resetStep === 2));
    if (resetStep3El) resetStep3El.classList.toggle('hidden', !(state.flow === 'reset' && state.resetStep === 3));
    if (resetStep4El) resetStep4El.classList.toggle('hidden', !(state.flow === 'reset' && state.resetStep === 4));
    if (resetDoneEl) resetDoneEl.classList.toggle('hidden', !(state.flow === 'reset' && state.resetStep === 5));

    if (state.email) {
      if (loginEmail) loginEmail.value = state.email;
      if (resetEmail) resetEmail.value = state.email;
    }
  }

  // Toggle help
  if (helpToggle) {
    helpToggle.addEventListener('click', () => {
      const expanded = helpToggle.getAttribute('aria-expanded') === 'true';
      helpToggle.setAttribute('aria-expanded', expanded ? 'false' : 'true');
      if (helpArea && helpArea.scrollIntoView) {
        helpArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  }

  // Tabs
  if (tabLogin) tabLogin.addEventListener('click', () => setTab('login'));
  if (tabReset) tabReset.addEventListener('click', () => setTab('reset'));

  // Login actions
  if (btnLoginForgot) btnLoginForgot.addEventListener('click', () => {
    state.resetStep = 1;
    setTab('reset');
  });

  if (btnLogin) btnLogin.addEventListener('click', async () => {
    const email = (loginEmail && 'value' in loginEmail ? loginEmail.value : '').trim().toLowerCase();
    const password = (loginPassword && 'value' in loginPassword ? loginPassword.value : '');
    state.email = email; store.save(state);
    try {
      const res = await api('/api/login/start', { email, password });
      if (res.requireMfa) {
        console.log('MFA code (login):', res.mfa);
        state.loginStep = 2; render(); store.save(state);
        setTimeout(() => { if (loginMfaCode && loginMfaCode.focus) loginMfaCode.focus(); }, 50);
      } else {
        state.loginStep = 3; render(); store.save(state);
      }
    } catch (e) {
      const msg = e && e.message ? e.message : 'Login failed';
      console.log('Login error:', msg);
      alert('Login failed. Please check details or try reset.');
    }
  });

  if (btnLoginMfa) btnLoginMfa.addEventListener('click', async () => {
    const code = (loginMfaCode && 'value' in loginMfaCode ? loginMfaCode.value : '').replace(/\\D/g, '').trim();
    try {
      await api('/api/login/verify', { code });
      state.loginStep = 3; render(); store.save(state);
    } catch (e) {
      console.log('MFA error:', e.message || 'Invalid code');
      alert('Invalid code. Please check Logs for the current code.');
    }
  });

  if (btnLoginBack) btnLoginBack.addEventListener('click', () => {
    state.loginStep = 1; render(); store.save(state);
  });

  if (btnAcceptPrivacy) btnAcceptPrivacy.addEventListener('click', () => {
    alert('Privacy statement accepted. Thank you.');
  });

  if (btnLogout) btnLogout.addEventListener('click', async () => {
    try { await api('/api/logout', {}); } catch {}
    state.loginStep = 1; render(); store.save(state);
  });

  // Reset flow actions
  if (btnResetToLogin) btnResetToLogin.addEventListener('click', () => {
    setTab('login');
  });

  function clientPasswordPolicy(pw) {
    if (pw.length < 12) return "Password must be at least 12 characters.";
    if (!/[a-z]/.test(pw)) return "Include a lowercase letter.";
    if (!/[A-Z]/.test(pw)) return "Include an uppercase letter.";
    if (!/[0-9]/.test(pw)) return "Include a number.";
    if (!/[^\\w\\s]/.test(pw)) return "Include a special character.";
    return "";
  }

  if (btnResetRequest) btnResetRequest.addEventListener('click', async () => {
    const email = (resetEmail && 'value' in resetEmail ? resetEmail.value : '').trim().toLowerCase();
    state.email = email; store.save(state);
    if (resetEmailMsg) resetEmailMsg.textContent = "Working...";
    try {
      const res = await api('/api/reset/request', { email });
      if (resetEmailMsg) resetEmailMsg.textContent = res && res.message ? res.message : 'If the account exists, instructions were sent. Check Logs.';
      state.resetStep = 2; render(); store.save(state);
    } catch (e) {
      if (resetEmailMsg) resetEmailMsg.textContent = 'Please wait before trying again.';
      console.log('Reset request throttled or failed:', e.message || '');
    }
  });

  if (btnVerifyCode) btnVerifyCode.addEventListener('click', async () => {
    const code = (resetCode && 'value' in resetCode ? resetCode.value : '').replace(/\\D/g, '').trim();
    if (verifyMsg) verifyMsg.textContent = 'Verifying...';
    try {
      await api('/api/reset/verify', { code });
      state.resetStep = 3; render(); store.save(state);
      if (verifyMsg) verifyMsg.textContent = 'Verified. Continue with MFA.';
    } catch (e) {
      if (verifyMsg) verifyMsg.textContent = 'Invalid or expired code. Please try again.';
    }
  });

  if (btnPasteLink) btnPasteLink.addEventListener('click', async () => {
    const url = new URL(window.location.href);
    const token = url.searchParams.get('token') || '';
    if (!token) {
      if (verifyMsg) verifyMsg.textContent = 'No token found in the address bar. Paste the link here by opening it first.';
      return;
    }
    if (verifyMsg) verifyMsg.textContent = 'Verifying link...';
    try {
      await api('/api/reset/verify', { token });
      state.resetStep = 3; render(); store.save(state);
      if (verifyMsg) verifyMsg.textContent = 'Verified. Continue with MFA.';
    } catch (e) {
      if (verifyMsg) verifyMsg.textContent = 'Invalid or expired link.';
    }
  });

  if (btnResetBackV) btnResetBackV.addEventListener('click', () => {
    state.resetStep = 2; render(); store.save(state);
  });

  if (btnResetMfa) btnResetMfa.addEventListener('click', async () => {
    const code = (resetMfa && 'value' in resetMfa ? resetMfa.value : '').replace(/\\D/g, '').trim();
    if (mfaMsg) mfaMsg.textContent = 'Checking code...';
    try {
      await api('/api/reset/mfa', { code });
      state.resetStep = 4; render(); store.save(state);
      if (mfaMsg) mfaMsg.textContent = '';
    } catch (e) {
      if (mfaMsg) mfaMsg.textContent = e.message || 'Invalid code. Please check Logs for the current code.';
    }
  });

  if (btnResetBackMfa) btnResetBackMfa.addEventListener('click', () => {
    state.resetStep = 3; render(); store.save(state);
  });

  if (btnUpdatePassword) btnUpdatePassword.addEventListener('click', async () => {
    const a = (newPassword && 'value' in newPassword ? newPassword.value : '');
    const b = (newPassword2 && 'value' in newPassword2 ? newPassword2.value : '');
    if (pwMsg) pwMsg.textContent = '';
    if (a !== b) { if (pwMsg) pwMsg.textContent = 'Passwords do not match.'; return; }
    const err = clientPasswordPolicy(a);
    if (err) { if (pwMsg) pwMsg.textContent = err; return; }
    if (pwMsg) pwMsg.textContent = 'Updating...';
    try {
      await api('/api/reset/password', { password: a });
      state.resetStep = 5; render(); store.save(state);
      if (pwMsg) pwMsg.textContent = '';
    } catch (e) {
      if (pwMsg) pwMsg.textContent = e.message || 'Could not update password.';
    }
  });

  if (btnGoLogin) btnGoLogin.addEventListener('click', () => {
    state.loginStep = 1; setTab('login');
  });

  // Resume state on load
  (function init() {
    const url = new URL(window.location.href);
    if (url.searchParams.get('token')) {
      state.flow = 'reset';
      state.resetStep = Math.max(state.resetStep, 2);
    }
    setTab(state.flow);
    render();
    if (state.email) {
      if (loginEmail) loginEmail.value = state.email;
      if (resetEmail) resetEmail.value = state.email;
    }
    console.log('This is a demo. No real emails are sent.');
    console.log('Security: All sensitive requests require a CSRF token and are rate-limited.');
  })();

})();
`;
}

// ==============================
// API Handlers
// ==============================

function getClientIP(req: Request): string {
  const h = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "";
  const ip = h.split(",")[0].trim();
  return ip || "127.0.0.1";
}

const JSON_HEADERS = () => {
  const h = securityHeaders();
  h.set("Content-Type", "application/json");
  return h;
};

// POST /api/reset/request
async function handleResetRequest(req: Request, session: Session): Promise<Response> {
  // CSRF validation first (Security 1: CSRF as first operation)
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  // Then rate limiting and input checks
  const ip = getClientIP(req);
  const rate = checkRate(ip, "reset-request:ip", 5, 60_000);
  if (!rate.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rate.retryAfter || 30));
    return new Response(JSON.stringify({ ok: false, error: "Too many requests. Please wait." }), { status: 429, headers: h });
  }

  const body = await req.json().catch(() => ({}));
  const email = String((body.email || "")).toLowerCase().trim();
  if (!email || !email.includes("@")) {
    // Artificial uniform delay
    await Bun.sleep(600);
    return new Response(JSON.stringify({ ok: true, message: "If the account exists, instructions were sent." , log: []}), { status: 200, headers: JSON_HEADERS() });
  }

  const rateAcc = checkRate(ip, `reset-request:${email}`, 3, 10 * 60_000);
  if (!rateAcc.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rateAcc.retryAfter || 60));
    return new Response(JSON.stringify({ ok: false, error: "Please wait before trying again." }), { status: 429, headers: h });
  }

  const user = usersByEmail.get(email);
  let response: any = { ok: true, message: `If the account exists, instructions were sent to ${maskEmail(email)}.`, log: [] as string[] };

  // Generate token, code, and link identically for both real and non-existent accounts
  const token = randId(32);
  const createdAt = now();
  const tokenHash = await sha256Hex(token);
  const code = numericCodeFromHex(tokenHash, 6);
  const url = new URL(req.url);
  const link = `${url.protocol}//${url.host}/?token=${encodeURIComponent(token)}`;

  if (user) {
    const rec: ResetTokenRecord = { token, userId: user.id, createdAt, used: false, shortCode: code, attempts: 0, mfaAttempts: 0, decoy: false };
    resetTokens.set(token, rec);
    resetCodes.set(code, token);
  } else {
    // Decoy token indistinguishable to client; passes verify/MFA but won't modify any account
    const fakeUserId = `decoy:${randId(8)}`;
    const rec: ResetTokenRecord = { token, userId: fakeUserId, createdAt, used: false, shortCode: code, attempts: 0, mfaAttempts: 0, decoy: true };
    resetTokens.set(token, rec);
    resetCodes.set(code, token);
  }

  response.log.push(`Reset verification link: ${link}`);
  response.log.push(`Short manual code: ${code}`);

  // Artificial fixed delay to normalize timing regardless of account existence
  await Bun.sleep(600);

  return new Response(JSON.stringify(response), { status: 200, headers: JSON_HEADERS() });
}

// POST /api/reset/verify
async function handleResetVerify(req: Request, session: Session): Promise<Response> {
  const ip = getClientIP(req);
  const rate = checkRate(ip, "reset-verify", 10, 60_000);
  if (!rate.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rate.retryAfter || 30));
    return new Response(JSON.stringify({ ok: false, error: "Too many attempts. Please slow down." }), { status: 429, headers: h });
  }
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  const data = await req.json().catch(() => ({}));
  const token = typeof data.token === "string" ? data.token : null;
  const code = typeof data.code === "string" ? data.code.trim() : null;

  let rec: ResetTokenRecord | undefined;
  if (token) rec = resetTokens.get(token);
  else if (code) {
    // numeric 6-digit codes only
    if (!/^\d{6}$/.test(code)) {
      return new Response(JSON.stringify({ ok: false, error: "Invalid or expired token." }), { status: 400, headers: JSON_HEADERS() });
    }
    const t = resetCodes.get(code);
    if (t) rec = resetTokens.get(t);
  }

  if (!rec) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid or expired token." }), { status: 400, headers: JSON_HEADERS() });
  }
  // Validate not used and not expired (15 minutes)
  if (rec.used || now() - rec.createdAt > 15 * 60_000) {
    return new Response(JSON.stringify({ ok: false, error: "Token expired. Please start over." }), { status: 400, headers: JSON_HEADERS() });
  }

  session.reset = { userId: rec.userId, token: rec.token, createdAt: now() };
  const mfa = await deriveMfaForReset(rec.token);
  mfaForReset.set(rec.token, mfa);

  const res = { ok: true, next: "mfa", log: [`MFA code for reset: ${mfa}`] };
  return new Response(JSON.stringify(res), { status: 200, headers: JSON_HEADERS() });
}

// POST /api/reset/mfa
async function handleResetMfa(req: Request, session: Session): Promise<Response> {
  const ip = getClientIP(req);
  const rate = checkRate(ip, "reset-mfa", 10, 60_000);
  if (!rate.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rate.retryAfter || 30));
    return new Response(JSON.stringify({ ok: false, error: "Too many attempts. Please slow down." }), { status: 429, headers: h });
  }
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  const reset = session.reset;
  if (!reset) {
    return new Response(JSON.stringify({ ok: false, error: "No reset session." }), { status: 400, headers: JSON_HEADERS() });
  }
  const rec = resetTokens.get(reset.token);
  if (!rec || rec.used || now() - rec.createdAt > 15 * 60_000) {
    return new Response(JSON.stringify({ ok: false, error: "Reset session expired." }), { status: 400, headers: JSON_HEADERS() });
  }
  const data = await req.json().catch(() => ({}));
  const codeRaw = String(data.code || "");
  const code = codeRaw.replace(/\D/g, "").trim();
  if (!/^\d{6}$/.test(code)) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid code." }), { status: 400, headers: JSON_HEADERS() });
  }
  const expect = mfaForReset.get(rec.token);
  rec.mfaAttempts++;
  if (rec.mfaAttempts > 10) {
    return new Response(JSON.stringify({ ok: false, error: "Too many attempts." }), { status: 429, headers: JSON_HEADERS() });
  }
  if (!expect || code !== expect) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid code." }), { status: 400, headers: JSON_HEADERS() });
  }
  reset.mfaVerified = true;
  return new Response(JSON.stringify({ ok: true, next: "password" }), { status: 200, headers: JSON_HEADERS() });
}

// POST /api/reset/password
async function handleResetPassword(req: Request, session: Session): Promise<Response> {
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  const reset = session.reset;
  if (!reset || !reset.mfaVerified) {
    return new Response(JSON.stringify({ ok: false, error: "Not authorized for password update." }), { status: 403, headers: JSON_HEADERS() });
  }
  const rec = resetTokens.get(reset.token);
  if (!rec || rec.used || now() - rec.createdAt > 15 * 60_000) {
    return new Response(JSON.stringify({ ok: false, error: "Reset session expired." }), { status: 400, headers: JSON_HEADERS() });
  }
  const data = await req.json().catch(() => ({}));
  const password = String(data.password || "");
  const val = validatePasswordPolicy(password);
  if (!val.ok) {
    return new Response(JSON.stringify({ ok: false, error: val.message || "Weak password." }), { status: 400, headers: JSON_HEADERS() });
  }

  // If this is a decoy token, behave as success without modifying any account
  if (rec.decoy) {
    rec.used = true;
    mfaForReset.delete(rec.token);
    resetCodes.delete(rec.shortCode);
    delete session.reset;
    return new Response(JSON.stringify({ ok: true, message: "Password updated." }), { status: 200, headers: JSON_HEADERS() });
  }

  const user = usersById.get(rec.userId);
  if (!user) {
    // Treat as generic success to avoid revealing account existence/misconfiguration
    rec.used = true;
    mfaForReset.delete(rec.token);
    resetCodes.delete(rec.shortCode);
    delete session.reset;
    return new Response(JSON.stringify({ ok: true, message: "Password updated." }), { status: 200, headers: JSON_HEADERS() });
  }

  const hash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
  user.passwordHash = hash;

  // Invalidate token, MFA, and prior sessions
  rec.used = true;
  mfaForReset.delete(rec.token);
  resetCodes.delete(rec.shortCode);
  for (const [sid, s] of sessions) {
    if (s.userId === user.id) sessions.delete(sid);
  }
  delete session.reset;

  return new Response(JSON.stringify({ ok: true, message: "Password updated." }), { status: 200, headers: JSON_HEADERS() });
}

// POST /api/login/start
async function handleLoginStart(req: Request, session: Session): Promise<Response> {
  const ip = getClientIP(req);
  const rate = checkRate(ip, "login-start", 8, 60_000);
  if (!rate.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rate.retryAfter || 30));
    return new Response(JSON.stringify({ ok: false, error: "Too many attempts. Please wait." }), { status: 429, headers: h });
  }
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  const data = await req.json().catch(() => ({}));
  const email = String(data.email || "").toLowerCase().trim();
  const password = String(data.password || "");
  const user = usersByEmail.get(email);
  if (!user) {
    await Bun.sleep(100);
    return new Response(JSON.stringify({ ok: false, error: "Invalid credentials." }), { status: 401, headers: JSON_HEADERS() });
  }
  const ok = await Bun.password.verify(password, user.passwordHash);
  if (!ok) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid credentials." }), { status: 401, headers: JSON_HEADERS() });
  }

  if (user.mfaEnabled) {
    const mfa = await deriveMfaForLogin(user.id);
    mfaForLogin.set(user.id, mfa);
    session.pendingLoginUserId = user.id;
    return new Response(JSON.stringify({ ok: true, requireMfa: true, log: [`MFA code (login): ${mfa}`], mfa }), { status: 200, headers: JSON_HEADERS() });
  } else {
    session.userId = user.id;
    return new Response(JSON.stringify({ ok: true, requireMfa: false }), { status: 200, headers: JSON_HEADERS() });
  }
}

// POST /api/login/verify
async function handleLoginVerify(req: Request, session: Session): Promise<Response> {
  const ip = getClientIP(req);
  const rate = checkRate(ip, "login-verify", 10, 60_000);
  if (!rate.ok) {
    const h = JSON_HEADERS();
    h.set("Retry-After", String(rate.retryAfter || 30));
    return new Response(JSON.stringify({ ok: false, error: "Too many attempts. Please wait." }), { status: 429, headers: h });
  }
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;

  const uid = session.pendingLoginUserId;
  if (!uid) {
    return new Response(JSON.stringify({ ok: false, error: "No pending login." }), { status: 400, headers: JSON_HEADERS() });
  }
  const data = await req.json().catch(() => ({}));
  const codeRaw = String(data.code || "");
  const code = codeRaw.replace(/\D/g, "").trim();
  if (!/^\d{6}$/.test(code)) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid code." }), { status: 401, headers: JSON_HEADERS() });
  }
  const expect = mfaForLogin.get(uid) || (await deriveMfaForLogin(uid));
  if (code !== expect) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid code." }), { status: 401, headers: JSON_HEADERS() });
  }
  session.userId = uid;
  delete session.pendingLoginUserId;
  mfaForLogin.delete(uid);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: JSON_HEADERS() });
}

// POST /api/logout
async function handleLogout(req: Request, session: Session): Promise<Response> {
  const csrfFail = await requireCsrf(req, session);
  if (csrfFail) return csrfFail;
  delete session.userId;
  delete session.pendingLoginUserId;
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: JSON_HEADERS() });
}

// ==============================
// Router and HTTPS Server
// ==============================

async function router(req: Request): Promise<Response> {
  try {
    const { session, setCookie } = await getOrCreateSession(req);
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method.toUpperCase();
    const isApi = path.startsWith("/api/");

    // Serve client JS
    if (method === "GET" && path === "/app.js") {
      const h = securityHeaders();
      h.set("Content-Type", "application/javascript; charset=utf-8");
      if (setCookie) h.set("Set-Cookie", setCookie);
      return new Response(clientJs(), { status: 200, headers: h });
    }

    if (method === "GET" && !isApi) {
      const html = spaHtml(session.csrf);
      const h = securityHeaders();
      h.set("Content-Type", "text/html; charset=utf-8");
      if (setCookie) h.set("Set-Cookie", setCookie);
      return new Response(html, { status: 200, headers: h });
    }

    // API endpoints
    if (method === "POST") {
      if (path === "/api/reset/request") return await handleResetRequest(req, session);
      if (path === "/api/reset/verify") return await handleResetVerify(req, session);
      if (path === "/api/reset/mfa") return await handleResetMfa(req, session);
      if (path === "/api/reset/password") return await handleResetPassword(req, session);
      if (path === "/api/login/start") return await handleLoginStart(req, session);
      if (path === "/api/login/verify") return await handleLoginVerify(req, session);
      if (path === "/api/logout") return await handleLogout(req, session);
    }

    // Unknown API or method
    if (isApi) {
      return new Response(JSON.stringify({ ok: false, error: "Not found" }), { status: 404, headers: JSON_HEADERS() });
    }

    // Fallback to SPA
    const h = securityHeaders();
    const html = spaHtml(session.csrf);
    h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html, { status: 200, headers: h });
  } catch (_err) {
    // Avoid leaking stack traces
    const h = JSON_HEADERS();
    return new Response(JSON.stringify({ ok: false, error: "Internal error" }), { status: 500, headers: h });
  }
}

// Start HTTPS server with mkcert certificates (Security: HTTPS + HSTS)
const server = Bun.serve({
  tls: {
    certFile: "certs/cert.pem",
    keyFile: "certs/key.pem",
  },
  port: 8443,
  fetch: router,
});

console.log(`HTTPS server running on https://localhost:${server.port}`);
