
/**
 * app.ts - Single-file HTTPS Bun server + SPA for Password Recovery System
 * Run with: bun app.ts
 *
 * This file implements:
 * - HTTPS server with TLS (certs/cert.pem, certs/key.pem)
 * - Strict security headers (HSTS, CSP with nonce, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
 * - In-memory stores for users, sessions, CSRF tokens, password reset tokens, MFA codes, and rate limiting
 * - SPA HTML with inline CSS/JS using CSP nonce (no inline event handlers)
 * - Client-side hash routing for: login, request reset, verify token, set new password, MFA verify, and success
 * - API endpoints for request-reset, verify-token, set-password, login, mfa-verify
 * - Strong password policy checks (client + server), bcrypt/argon2id hashing via Bun.password.hash
 * - Anti-CSRF on all sensitive POST routes
 * - Rate limiting on sensitive POST routes
 * - Input sanitization and escaping helpers (server + client)
 * - Logs panel mirroring console.log and "For demo" panel showing mock deliveries
 *
 * Security Comments map to "Security Evaluation Requirements" where relevant in code blocks below.
 */

type User = {
  id: string;
  username: string;
  email: string;
  passwordHash: string; // argon2id
  mfaEnabled: boolean;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  ip?: string;
  canSetPassword?: boolean;
  resetUserId?: string | null;
  mfaPending?: boolean;
  mfaCode?: string | null;
  mfaGeneratedAt?: number | null;
  authenticated?: boolean;
  // simple progress hints for inclusivity (pause/resume)
  lastView?: string;
};

type ResetToken = {
  token: string; // random base64url
  code: string; // human 6-digit
  userId: string | null;
  createdAt: number;
  expiresAt: number;
  used: boolean;
  sessionId?: string;
};

type RateRecord = {
  count: number;
  last: number;
  blockedUntil: number;
};

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>(); // key: token
const rateMap = new Map<string, RateRecord>();

// Utility: base64url encode
function b64url(buf: Uint8Array): string {
  const b64 = Buffer.from(buf).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomId(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function now(): number {
  return Date.now();
}

function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sanitizeInput(input: unknown, maxLen = 256): string {
  let s = String(input ?? "");
  s = s.replace(/[\u0000-\u001F\u007F]/g, ""); // strip control chars
  s = s.replace(/\s+/g, " ").trim();
  s = s.slice(0, maxLen);
  return s;
}

function parseCookies(header: string | null): Record<string, string> {
  const obj: Record<string, string> = {};
  if (!header) return obj;
  header.split(";").forEach((p) => {
    const [k, ...rest] = p.split("=");
    if (!k) return;
    const key = k.trim();
    const val = rest.join("=").trim();
    if (!key) return;
    obj[key] = decodeURIComponent(val || "");
  });
  return obj;
}

// Security: CSRF token unique per session
function ensureSession(req: Request, ip?: string): { session: Session; setCookies: string[] } {
  const cookies = parseCookies(req.headers.get("cookie"));
  let sid = cookies["sid"];
  let session = sid ? sessions.get(sid) : undefined;
  const setCookies: string[] = [];
  if (!session) {
    sid = randomId(32);
    const csrf = randomId(16);
    session = {
      id: sid,
      csrf,
      createdAt: now(),
      lastSeenAt: now(),
      ip,
      authenticated: false,
      canSetPassword: false,
      resetUserId: null,
      mfaPending: false,
      mfaCode: null,
      mfaGeneratedAt: null,
      lastView: "login",
    };
    sessions.set(sid, session);
  } else {
    session.lastSeenAt = now();
    if (ip && !session.ip) session.ip = ip;
  }
  // Secure cookies
  setCookies.push(
    `sid=${encodeURIComponent(session.id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000`
  );
  // CSRF token cookie (HttpOnly) - readable only by server; we also embed token in HTML meta for client usage.
  setCookies.push(
    `csrf=${encodeURIComponent(session.csrf)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000`
  );
  return { session, setCookies };
}

function securityHeaders(opts: { csp?: string; hsts?: boolean } = {}): HeadersInit {
  const h: HeadersInit = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy":
      "accelerometer=(), camera=(), microphone=(), geolocation=(), gyroscope=(), magnetometer=(), payment=(), usb=()",
    "Cache-Control": "no-store",
  };
  if (opts.csp) (h as any)["Content-Security-Policy"] = opts.csp;
  if (opts.hsts !== false) {
    (h as any)["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
  }
  return h;
}

// Security: Rate limiting per session+IP+route with exponential backoff
function rateKey(session: Session, route: string, ip?: string) {
  return `${session.id}|${ip || "noip"}|${route}`;
}
function rateLimitCheck(session: Session, route: string, ip?: string): { ok: boolean; headers?: HeadersInit; retryAfter?: number } {
  const key = rateKey(session, route, ip);
  const rec = rateMap.get(key) || { count: 0, last: 0, blockedUntil: 0 };
  const t = now();
  // decay count after 60 seconds
  if (t - rec.last > 60_000) {
    rec.count = 0;
  }
  rec.last = t;
  if (t < rec.blockedUntil) {
    const retryAfter = Math.ceil((rec.blockedUntil - t) / 1000);
    return { ok: false, headers: { "Retry-After": String(retryAfter) }, retryAfter };
  }
  rec.count += 1;
  if (rec.count > 5) {
    const backoff = Math.min(120_000, 5_000 * Math.pow(2, rec.count - 6)); // exponential backoff
    rec.blockedUntil = t + backoff;
  }
  rateMap.set(key, rec);
  return { ok: true };
}

function jsonResponse(
  body: any,
  init: { status?: number; headers?: HeadersInit; csp?: string } = {}
) {
  const headers: HeadersInit = {
    "Content-Type": "application/json; charset=utf-8",
    ...(init.headers || {}),
    ...securityHeaders({ csp: init.csp }),
  };
  return new Response(JSON.stringify(body), { status: init.status || 200, headers });
}

function badRequest(message = "Bad Request") {
  return jsonResponse({ ok: false, message }, { status: 400 });
}
function forbidden(message = "Forbidden") {
  return jsonResponse({ ok: false, message }, { status: 403 });
}

// Security: server-side CSRF validation
async function requireCsrf(req: Request, session: Session): Promise<boolean> {
  const token = req.headers.get("x-csrf-token") || "";
  if (!token || token !== session.csrf) {
    return false;
  }
  return true;
}

// Password policy (both client and server use same logic)
function checkPasswordPolicy(pw: string): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (pw.length < 12) reasons.push("At least 12 characters");
  if (!/[a-z]/.test(pw)) reasons.push("Include lowercase letters");
  if (!/[A-Z]/.test(pw)) reasons.push("Include uppercase letters");
  if (!/[0-9]/.test(pw)) reasons.push("Include a number");
  if (!/[^\w\s]/.test(pw)) reasons.push("Include a symbol");
  if (/\s/.test(pw)) reasons.push("No spaces allowed");
  return { ok: reasons.length === 0, reasons };
}

// Demo data: one user (avoid private identifiers in UI)
const DEMO_USER_ID = "u1";
async function initDemoUser() {
  const hash = await Bun.password.hash("StrongPassw0rd!", {
    algorithm: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
  });
  users.set(DEMO_USER_ID, {
    id: DEMO_USER_ID,
    username: "helena",
    email: "patient@example.com",
    passwordHash: hash,
    mfaEnabled: true,
  });
}

function deriveHumanCodeFromToken(token: string): string {
  // deterministic 6-digit code from token hash
  let acc = 0;
  for (let i = 0; i < token.length; i++) {
    acc = (acc * 31 + token.charCodeAt(i)) >>> 0;
  }
  const code = (acc % 1_000_000).toString().padStart(6, "0");
  return code;
}

function generateResetToken(userId: string | null, sessionId: string): ResetToken {
  const token = randomId(32);
  const code = deriveHumanCodeFromToken(token);
  const createdAt = now();
  const expiresAt = createdAt + 15 * 60_000; // 15 minutes
  const rt: ResetToken = { token, code, userId, createdAt, expiresAt, used: false, sessionId };
  resetTokens.set(token, rt);
  return rt;
}

function findTokenByCode(code: string): ResetToken | undefined {
  let found: ResetToken | undefined;
  for (const t of resetTokens.values()) {
    if (t.code === code) {
      // pick the most recent non-expired
      if (!found || t.createdAt > found.createdAt) found = t;
    }
  }
  return found;
}

// MFA generation: deterministic per-session when login succeeds
function generateMfaForSession(session: Session): string {
  const seed = session.id + "|" + session.csrf + "|" + session.createdAt;
  let acc = 7;
  for (let i = 0; i < seed.length; i++) acc = (acc * 33 + seed.charCodeAt(i)) >>> 0;
  const code = (acc % 1_000_000).toString().padStart(6, "0");
  session.mfaCode = code;
  session.mfaPending = true;
  session.mfaGeneratedAt = now();
  return code;
}

// Build CSP per response
function buildCSP(nonce: string): string {
  // Security: CSP with nonce, disallow inline except our nonce, no external
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");
}

// Render SPA HTML (Security: outputs escaped; Inline JS/CSS via CSP nonce)
function renderHTML(session: Session, nonce: string): string {
  const csrf = escapeHTML(session.csrf);
  const lastView = escapeHTML(session.lastView || "login");
  // No user identifiers printed
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital Account Access — Secure Recovery</title>
  <meta id="csrf-meta" data-token="${csrf}">
  <meta id="session-view" data-last="${lastView}">
  <style nonce="${nonce}">
    /* Inclusivity & Accessibility (Requirements: Inclusivity) */
    :root {
      --bg: #f7fafc;
      --fg: #1a202c;
      --muted: #4a5568;
      --primary: #2563eb;
      --accent: #16a34a;
      --warn: #b91c1c;
      --card: #ffffff;
      --focus: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background: var(--bg); color: var(--fg);
    }
    header {
      background: #0f172a; color: #fff; padding: 16px;
    }
    header h1 { margin: 0 0 4px 0; font-size: 20px; }
    header p { margin: 0; color: #cbd5e1; font-size: 14px; }
    main { max-width: 860px; margin: 24px auto; padding: 0 12px; }
    .layout { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
    .card {
      background: var(--card); border-radius: 10px; padding: 16px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }
    .step-header { display:flex; align-items:center; justify-content:space-between; margin-bottom: 12px; }
    .progress { width: 100%; height: 8px; background: #e5e7eb; border-radius: 999px; overflow: hidden; margin-top: 8px; }
    .progress > div { height: 100%; background: var(--primary); width: 0%; transition: width .3s; }
    nav a { color: #bfdbfe; margin-right: 16px; text-decoration: none; }
    nav a:focus { outline: 3px solid var(--focus); border-radius: 4px; }
    h2 { margin: 0 0 8px 0; }
    .muted { color: var(--muted); font-size: 14px; }
    label { display:block; margin: 10px 0 6px; }
    input[type="text"], input[type="password"] {
      width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 8px;
    }
    button {
      background: var(--primary); color: #fff; border: 0; padding: 10px 16px; border-radius: 8px; cursor: pointer;
      margin-top: 12px; font-weight: 600;
    }
    button.secondary { background: #374151; }
    button.link { background: transparent; color: var(--primary); text-decoration: underline; padding: 6px 4px; }
    .row { display:flex; gap: 8px; align-items:center; }
    .success { color: var(--accent); }
    .error { color: var(--warn); }
    .info { color: #1d4ed8; }
    .sr { position:absolute; left:-9999px; width:1px; height:1px; overflow:hidden; }
    .hidden { display: none !important; }

    .panel { font-size: 12px; }
    #logs { height: 180px; overflow: auto; background: #0b1020; color: #e2e8f0; padding: 8px; border-radius: 8px; white-space: pre-wrap; }
    #demo { background: #fefce8; border: 1px dashed #f59e0b; }
    .help { background: #ecfeff; border: 1px solid #06b6d4; }
    .footer-note { font-size: 12px; color: var(--muted); margin-top: 8px; }

    .password-tips { margin-top: 6px; font-size: 12px; }
    .badge { display:inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; margin-left: 8px; background: #e2e8f0;}
    .badge.good { background: #dcfce7; color: #166534; }
    .badge.bad { background: #fee2e2; color: #991b1b; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }

    .linklike { color: var(--primary); cursor: pointer; text-decoration: underline; }

  </style>
</head>
<body>
  <header role="banner">
    <div class="row" style="justify-content: space-between;">
      <div>
        <h1>Secure Access Portal</h1>
        <p>Log in to accept the updated privacy conditions and manage your appointments.</p>
      </div>
      <nav aria-label="Helpful links">
        <a href="#/help" id="helpLink">Help</a>
      </nav>
    </div>
    <div class="progress" aria-hidden="true"><div id="progressBar"></div></div>
  </header>

  <main id="app" role="main" aria-live="polite">
    <div class="layout">
      <section id="views" class="card" aria-label="Steps">
        <!-- Views rendered client-side -->
        <div id="view-login" class="view">
          <div class="step-header">
            <h2>1. Log in</h2>
            <span class="badge" id="authStatus">Not signed in</span>
          </div>
          <p class="muted">Use your account to continue. If you can't remember your password, choose "I forgot my password" below.</p>
          <form id="form-login" autocomplete="off" novalidate>
            <label for="login-id">Username or email</label>
            <input id="login-id" type="text" inputmode="email" autocomplete="username" required>
            <label for="login-pw">Password</label>
            <input id="login-pw" type="password" autocomplete="current-password" required>
            <div class="row" style="justify-content: space-between;">
              <button type="submit">Continue</button>
              <button type="button" id="goto-reset" class="secondary">I forgot my password</button>
            </div>
            <div id="login-msg" class="muted" role="status"></div>
          </form>
        </div>

        <div id="view-request-reset" class="view hidden">
          <div class="step-header">
            <h2>2. Request password reset</h2>
          </div>
          <p class="muted">We’ll send a reset link and a code. You can use either the link or enter the code manually. For the demo, they appear in the panel on the right.</p>
          <form id="form-request-reset" autocomplete="off" novalidate>
            <label for="reset-id">Account identifier</label>
            <input id="reset-id" type="text" inputmode="email" placeholder="username or email" required>
            <button type="submit">Send reset instructions</button>
            <div id="reset-msg" class="muted" role="status"></div>
          </form>
          <div class="footer-note">We never disclose whether an account exists. Keep this page open—you can take a break and continue anytime.</div>
        </div>

        <div id="view-verify-token" class="view hidden">
          <div class="step-header">
            <h2>3. Verify reset</h2>
          </div>
          <p class="muted">Paste the link token or type the 6‑digit code you received.</p>
          <form id="form-verify-token" autocomplete="off" novalidate>
            <div class="grid">
              <div>
                <label for="verify-token">Verification link token</label>
                <input id="verify-token" type="text" placeholder="token from the link">
              </div>
              <div>
                <label for="verify-code">Or 6-digit code</label>
                <input id="verify-code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="e.g. 123456">
              </div>
            </div>
            <button type="submit">Verify</button>
            <div id="verify-msg" class="muted" role="status"></div>
          </form>
        </div>

        <div id="view-set-password" class="view hidden">
          <div class="step-header">
            <h2>4. Choose a new password</h2>
          </div>
          <p class="muted">Pick a strong password you can remember. Aim for 3+ words or a mix of letters, numbers, and symbols.</p>
          <form id="form-set-password" autocomplete="off" novalidate>
            <label for="new-pw">New password</label>
            <input id="new-pw" type="password" autocomplete="new-password" required>
            <label for="new-pw2">Confirm new password</label>
            <input id="new-pw2" type="password" autocomplete="new-password" required>
            <div id="pw-tips" class="password-tips"></div>
            <button type="submit">Save new password</button>
            <div id="setpw-msg" class="muted" role="status"></div>
          </form>
        </div>

        <div id="view-mfa" class="view hidden">
          <div class="step-header">
            <h2>5. Verify with code</h2>
          </div>
          <p class="muted">Enter the 6‑digit code from your authenticator or secure message.</p>
          <form id="form-mfa" autocomplete="off" novalidate>
            <label for="mfa-code">6-digit code</label>
            <input id="mfa-code" type="text" inputmode="numeric" maxlength="6" required>
            <button type="submit">Verify</button>
            <div id="mfa-msg" class="muted" role="status"></div>
          </form>
        </div>

        <div id="view-success" class="view hidden">
          <div class="step-header">
            <h2>6. You're all set</h2>
            <span class="badge good">Signed in</span>
          </div>
          <p class="success">You’re signed in. You can now accept the updated privacy statement and continue with your appointment booking.</p>
          <p class="muted">You can close this page or return to your account dashboard.</p>
          <p><span class="linklike" id="back-to-login">Back to start</span></p>
        </div>

        <div id="view-help" class="view hidden">
          <div class="step-header">
            <h2>Help & Safety</h2>
          </div>
          <div class="card help">
            <ul>
              <li>Stay calm—there are no time limits. You can pause and come back anytime.</li>
              <li>We will never ask for your password or codes by email or phone.</li>
              <li>Only use this secure site (check the lock icon and “https”).</li>
              <li>If a link looks suspicious, manually visit this site and use the code instead.</li>
              <li>Strong passwords: at least 12 characters with a mix of types, or use a passphrase.</li>
            </ul>
            <p><span class="linklike" id="help-back">Return to previous step</span></p>
          </div>
        </div>
      </section>

      <aside aria-label="Guidance and logs" class="card panel">
        <h3>For demo</h3>
        <div id="demo" class="card">
          <div><strong>Reset link:</strong> <span id="demo-link">(none yet)</span></div>
          <div><strong>Manual token:</strong> <span id="demo-token">(none)</span></div>
          <div><strong>Reset code:</strong> <span id="demo-code">(none)</span></div>
          <div><strong>MFA code:</strong> <span id="demo-mfa">(none)</span></div>
        </div>
        <h3 style="margin-top: 16px;">Logs</h3>
        <div id="logs" aria-live="polite"></div>
      </aside>
    </div>
  </main>

  <footer class="card" style="max-width: 860px; margin: 16px auto;">
    <small class="muted">Security: HTTPS enforced, HSTS, CSP, CSRF protection, rate limiting, password hashing, MFA (demo). No external calls.</small>
  </footer>

  <script nonce="${nonce}">
  // Client-side code
  (function(){
    'use strict';

    // Security: prevent DOM XSS - helpers
    function sanitizeInput(s) {
      if (s == null) return '';
      return String(s).replace(/[\\u0000-\\u001F\\u007F]/g, '').replace(/\\s+/g, ' ').trim().slice(0, 256);
    }
    function setText(el, text) { el.textContent = String(text || ''); }
    function qs(sel) { return document.querySelector(sel); }
    function qsa(sel) { return Array.from(document.querySelectorAll(sel)); }

    // Logs panel mirrors console.log
    const logsEl = qs('#logs');
    const originalLog = console.log.bind(console);
    console.log = function(...args) {
      originalLog(...args);
      const msg = args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
      const line = document.createElement('div');
      line.textContent = msg;
      logsEl.appendChild(line);
      logsEl.scrollTop = logsEl.scrollHeight;
    };

    const csrfToken = qs('#csrf-meta')?.getAttribute('data-token') || '';
    const sessionLast = qs('#session-view')?.getAttribute('data-last') || 'login';

    const views = {
      login: qs('#view-login'),
      requestReset: qs('#view-request-reset'),
      verifyToken: qs('#view-verify-token'),
      setPassword: qs('#view-set-password'),
      mfa: qs('#view-mfa'),
      success: qs('#view-success'),
      help: qs('#view-help')
    };

    const progressOrder = ['login','requestReset','verifyToken','setPassword','mfa','success'];
    function setProgress(view) {
      const idx = Math.max(0, progressOrder.indexOf(view));
      const pct = Math.round(((idx) / (progressOrder.length-1)) * 100);
      const bar = qs('#progressBar');
      bar.style.width = pct + '%';
      const authBadge = qs('#authStatus');
      if (view === 'success') { authBadge.textContent = 'Signed in'; authBadge.classList.add('good'); }
      else { authBadge.textContent = 'Not signed in'; authBadge.classList.remove('good'); }
    }

    function show(view) {
      Object.values(views).forEach(v => v.classList.add('hidden'));
      const v = views[view];
      if (v) v.classList.remove('hidden');
      setProgress(view);
      // keep last view in history-free way
      window.history.replaceState({}, '', window.location.pathname + window.location.search + '#/' + view);
    }

    // API helper with CSRF
    async function api(path, data) {
      const res = await fetch(path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(data || {})
      });
      const json = await res.json().catch(() => ({ ok: false, message: 'Invalid response' }));
      return json;
    }

    // Password policy check (same as server)
    function checkPasswordPolicy(pw) {
      const reasons = [];
      if (pw.length < 12) reasons.push('At least 12 characters');
      if (!/[a-z]/.test(pw)) reasons.push('Include lowercase letters');
      if (!/[A-Z]/.test(pw)) reasons.push('Include uppercase letters');
      if (!/[0-9]/.test(pw)) reasons.push('Include a number');
      if (!/[^\\w\\s]/.test(pw)) reasons.push('Include a symbol');
      if (/\\s/.test(pw)) reasons.push('No spaces allowed');
      return { ok: reasons.length === 0, reasons };
    }

    // Demo panel helpers
    function updateDemo({ link, token, code, mfa }) {
      if (link) setText(qs('#demo-link'), link);
      if (token) setText(qs('#demo-token'), token);
      if (code) setText(qs('#demo-code'), code);
      if (mfa) setText(qs('#demo-mfa'), mfa);
    }

    // Forms wiring
    const loginForm = qs('#form-login');
    const resetForm = qs('#form-request-reset');
    const verifyForm = qs('#form-verify-token');
    const setPwForm = qs('#form-set-password');
    const mfaForm = qs('#form-mfa');

    qs('#goto-reset').addEventListener('click', () => show('requestReset'));
    qs('#helpLink').addEventListener('click', (e) => { e.preventDefault(); show('help'); });
    qs('#help-back').addEventListener('click', () => window.history.back());
    qs('#back-to-login').addEventListener('click', () => show('login'));

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = sanitizeInput(qs('#login-id').value);
      const pw = sanitizeInput(qs('#login-pw').value);
      setText(qs('#login-msg'), 'Checking...');
      const res = await api('/api/login', { identifier: id, password: pw });
      // Always move to MFA to avoid enumeration. If valid, server will have set a code.
      if (res && res.demoMfaCode) {
        console.log('MFA code (demo):', res.demoMfaCode);
        updateDemo({ mfa: res.demoMfaCode });
      }
      setText(qs('#login-msg'), 'If the credentials are correct, you will be asked for a code.');
      show('mfa');
    });

    resetForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = sanitizeInput(qs('#reset-id').value);
      setText(qs('#reset-msg'), 'Sending instructions...');
      const res = await api('/api/request-reset', { identifier: id });
      if (res && res.demo && res.demo.token) {
        console.log('Password reset link (demo):', res.demo.link);
        console.log('Manual token (demo):', res.demo.token);
        console.log('Human code (demo):', res.demo.code);
        updateDemo({ link: res.demo.link, token: res.demo.token, code: res.demo.code });
      }
      setText(qs('#reset-msg'), 'If the account exists, a reset message has been sent. Use the link or code.');
      show('verifyToken');
    });

    verifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = sanitizeInput(qs('#verify-token').value);
      const code = sanitizeInput(qs('#verify-code').value);
      setText(qs('#verify-msg'), 'Verifying...');
      const res = await api('/api/verify-token', { tokenOrCode: token || code });
      if (res && res.canProceed) {
        setText(qs('#verify-msg'), 'Code accepted. You can set a new password.');
        show('setPassword');
      } else {
        setText(qs('#verify-msg'), 'If the code is valid, you can continue. Please check and try again.');
      }
    });

    // Password strength feedback
    function updatePwTips() {
      const pw = qs('#new-pw').value || '';
      const pol = checkPasswordPolicy(pw);
      const el = qs('#pw-tips');
      if (pw.length === 0) { el.textContent = 'Requirements: 12+ chars, upper+lower+number+symbol, no spaces.'; return; }
      if (pol.ok) { el.innerHTML = ''; const span = document.createElement('span'); span.className = 'badge good'; span.textContent = 'Looks strong'; el.appendChild(span); }
      else {
        el.innerHTML = '';
        pol.reasons.forEach(r => {
          const s = document.createElement('div');
          s.className = 'badge bad';
          s.textContent = r;
          el.appendChild(s);
        });
      }
    }
    qs('#new-pw').addEventListener('input', updatePwTips);
    qs('#new-pw2').addEventListener('input', updatePwTips);

    setPwForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pw1 = qs('#new-pw').value || '';
      const pw2 = qs('#new-pw2').value || '';
      if (pw1 !== pw2) { setText(qs('#setpw-msg'), 'Passwords do not match.'); return; }
      const pol = checkPasswordPolicy(pw1);
      if (!pol.ok) { setText(qs('#setpw-msg'), 'Please improve: ' + pol.reasons.join(', ')); return; }
      setText(qs('#setpw-msg'), 'Saving...');
      const res = await api('/api/set-password', { newPassword: pw1 });
      if (res && res.ok) {
        setText(qs('#setpw-msg'), 'Password updated. Please log in with your new password.');
        show('login');
      } else {
        setText(qs('#setpw-msg'), 'Unable to update password. Please try again.');
      }
    });

    mfaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = sanitizeInput(qs('#mfa-code').value);
      setText(qs('#mfa-msg'), 'Checking code...');
      const res = await api('/api/mfa-verify', { code });
      if (res && res.success) {
        setText(qs('#mfa-msg'), 'Success!');
        show('success');
      } else {
        setText(qs('#mfa-msg'), 'If the code is correct, you will continue. Please try again.');
      }
    });

    // Routing: simple hash router + token in query support
    function parseHash() {
      const h = window.location.hash.replace(/^#\\/?/, '');
      const [path, q] = h.split('?');
      const query = {};
      if (q) q.split('&').forEach(pair => {
        const [k,v] = pair.split('=');
        if (k) query[decodeURIComponent(k)] = decodeURIComponent(v || '');
      });
      return { path: path || 'login', query };
    }

    function route() {
      const { path, query } = parseHash();
      // if token present in URL query (either hash or normal query)
      const search = new URLSearchParams(window.location.search);
      const tokenFromSearch = search.get('token');
      const tokenFromHash = query['token'];
      if ((path === 'verify' || path === 'verifyToken') && (tokenFromSearch || tokenFromHash)) {
        const input = qs('#verify-token');
        if (input && (tokenFromSearch || tokenFromHash)) {
          input.value = sanitizeInput(tokenFromSearch || tokenFromHash);
        }
      }
      if (path === 'help') show('help');
      else if (path === 'request' || path === 'requestReset') show('requestReset');
      else if (path === 'verify' || path === 'verifyToken') show('verifyToken');
      else if (path === 'setPassword') show('setPassword');
      else if (path === 'mfa') show('mfa');
      else if (path === 'success') show('success');
      else show('login');
    }

    window.addEventListener('hashchange', route);

    // Initial route selection
    if (window.location.search.includes('token=')) {
      window.location.hash = '#/verifyToken';
    } else if (sessionLast) {
      // restore last known view gently for inclusivity
      window.location.hash = '#/' + sessionLast;
    }
    route();

    console.log('Welcome. This panel shows secure mock deliveries and actions.');
  })();
  </script>
</body>
</html>`;
}

// API routing
async function handleAPI(req: Request, server: any, session: Session): Promise<Response> {
  const url = new URL(req.url);
  const ip = (server?.requestIP?.(req)?.address as string) || req.headers.get("x-forwarded-for") || "";
  const csp = buildCSP(randomId(12)); // minimal nonce for API responses (no inline code), keep consistent CSP baseline
  const readJson = async () => {
    try {
      return await req.json();
    } catch {
      return {};
    }
  };

  if (req.method !== "POST") {
    return jsonResponse({ ok: false, message: "Method not allowed" }, { status: 405, csp });
  }

  // CSRF required
  if (!(await requireCsrf(req, session))) {
    return forbidden("CSRF token invalid");
  }

  if (url.pathname === "/api/request-reset") {
    const rl = rateLimitCheck(session, "request-reset", ip);
    if (!rl.ok) return jsonResponse({ ok: false, message: "Too many requests. Please wait." }, { status: 429, headers: rl.headers, csp });

    const body = await readJson();
    const identifier = sanitizeInput(body?.identifier);
    // Do not reveal if user exists (Security: Avoid user enumeration)
    // We will generate a token each time. Only tokens bound to a real user will allow proceeding.
    let userId: string | null = null;
    for (const u of users.values()) {
      if (u.username.toLowerCase() === identifier.toLowerCase() || u.email.toLowerCase() === identifier.toLowerCase()) {
        userId = u.id;
        break;
      }
    }
    const rt = generateResetToken(userId, session.id);
    const origin = url.origin.replace("http:", "https:"); // enforce https link
    const link = `${origin}/#/verify?token=${encodeURIComponent(rt.token)}`;
    // Mirror "delivery" via console in the browser — return for demo
    return jsonResponse({
      ok: true,
      message: "If the account exists, you will receive instructions.",
      demo: { token: rt.token, code: rt.code, link }
    }, { csp });
  }

  if (url.pathname === "/api/verify-token") {
    const rl = rateLimitCheck(session, "verify-token", ip);
    if (!rl.ok) return jsonResponse({ ok: false, message: "Too many requests. Please wait." }, { status: 429, headers: rl.headers, csp });

    const body = await readJson();
    const tokenOrCode = sanitizeInput(body?.tokenOrCode);
    let rt: ResetToken | undefined = resetTokens.get(tokenOrCode);
    if (!rt) {
      // allow manual code submission
      if (/^[0-9]{6}$/.test(tokenOrCode)) {
        rt = findTokenByCode(tokenOrCode);
      }
    }
    const t = now();
    let canProceed = false;
    if (rt && !rt.used && t < rt.expiresAt && rt.userId) {
      rt.used = true; // single-use (Security: tokens single-use and short-lived)
      session.canSetPassword = true;
      session.resetUserId = rt.userId;
      canProceed = true;
    }
    return jsonResponse({ ok: true, canProceed, message: "If valid, you may continue." }, { csp });
  }

  if (url.pathname === "/api/set-password") {
    const rl = rateLimitCheck(session, "set-password", ip);
    if (!rl.ok) return jsonResponse({ ok: false, message: "Too many requests. Please wait." }, { status: 429, headers: rl.headers, csp });

    if (!session.canSetPassword || !session.resetUserId) {
      // Security: Access control to sensitive action (Broken Access Control prevention)
      return forbidden("Not authorized for this action");
    }
    const body = await readJson();
    const newPassword = String(body?.newPassword || "");
    const policy = checkPasswordPolicy(newPassword);
    if (!policy.ok) {
      return jsonResponse({ ok: false, message: "Password does not meet policy", reasons: policy.reasons }, { status: 400, csp });
    }
    const user = users.get(session.resetUserId);
    if (!user) {
      return jsonResponse({ ok: false, message: "Unexpected error" }, { status: 500, csp });
    }
    const hash = await Bun.password.hash(newPassword, {
      algorithm: "argon2id",
      memoryCost: 19456,
      timeCost: 2,
    });
    user.passwordHash = hash;
    // Clear reset state
    session.canSetPassword = false;
    session.resetUserId = null;
    return jsonResponse({ ok: true, message: "Password updated." }, { csp });
  }

  if (url.pathname === "/api/login") {
    const rl = rateLimitCheck(session, "login", ip);
    if (!rl.ok) return jsonResponse({ ok: false, message: "Too many requests. Please wait." }, { status: 429, headers: rl.headers, csp });

    const body = await readJson();
    const identifier = sanitizeInput(body?.identifier);
    const password = String(body?.password || "");
    let user: User | undefined;
    for (const u of users.values()) {
      if (u.username.toLowerCase() === identifier.toLowerCase() || u.email.toLowerCase() === identifier.toLowerCase()) {
        user = u; break;
      }
    }
    let demoMfaCode: string | undefined;
    if (user && await Bun.password.verify(password, user.passwordHash)) {
      // Valid credentials; generate MFA
      demoMfaCode = generateMfaForSession(session);
      // For demo: send code back for console.log panel
      return jsonResponse({
        ok: true,
        message: "If the credentials are correct, you will be asked for a code.",
        demoMfaCode
      }, { csp });
    } else {
      // Do not reveal anything; still generic response
      return jsonResponse({
        ok: true,
        message: "If the credentials are correct, you will be asked for a code."
      }, { csp });
    }
  }

  if (url.pathname === "/api/mfa-verify") {
    const rl = rateLimitCheck(session, "mfa-verify", ip);
    if (!rl.ok) return jsonResponse({ ok: false, message: "Too many requests. Please wait." }, { status: 429, headers: rl.headers, csp });

    const body = await readJson();
    const code = sanitizeInput(body?.code);
    let success = false;
    const ttl = 10 * 60_000;
    if (session.mfaPending && session.mfaCode && session.mfaGeneratedAt && now() - session.mfaGeneratedAt < ttl) {
      if (code === session.mfaCode) {
        success = true;
        session.authenticated = true;
        session.mfaPending = false;
        session.mfaCode = null;
        session.mfaGeneratedAt = null;
      }
    }
    return jsonResponse({ ok: true, success, message: success ? "Signed in." : "If the code is correct, you will continue." }, { csp });
  }

  return jsonResponse({ ok: false, message: "Not found" }, { status: 404, csp });
}

// Main request handler
async function handler(req: Request, server: any): Promise<Response> {
  // Enforce HTTPS scheme in links and set strict headers per response
  const ip = (server?.requestIP?.(req)?.address as string) || req.headers.get("x-forwarded-for") || "";
  const { session, setCookies } = ensureSession(req, ip);
  const url = new URL(req.url);

  if (url.pathname.startsWith("/api/")) {
    const res = await handleAPI(req, server, session);
    const headers = new Headers(res.headers);
    // propagate cookies and headers
    for (const c of setCookies) headers.append("Set-Cookie", c);
    return new Response(await res.text(), { status: res.status, headers });
  }

  if (url.pathname === "/") {
    const nonce = randomId(12);
    const csp = buildCSP(nonce);
    const html = renderHTML(session, nonce);
    const headers: HeadersInit = {
      "Content-Type": "text/html; charset=utf-8",
      ...securityHeaders({ csp }),
    };
    setCookies.push(`lastView=${encodeURIComponent(session.lastView || "login")}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000`);
    const resHeaders = new Headers(headers);
    for (const c of setCookies) resHeaders.append("Set-Cookie", c);
    return new Response(html, { status: 200, headers: resHeaders });
  }

  return new Response("Not found", { status: 404, headers: securityHeaders() });
}

// Initialize demo user and start server
await initDemoUser();

// HTTPS server with provided certificates (Requirements: Security Misconfiguration - HTTPS enforced, HSTS, CSP)
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");

const server = Bun.serve({
  port: 8443,
  tls: {
    cert: await certFile.text(),
    key: await keyFile.text(),
  },
  fetch: handler,
});

console.log(`HTTPS server running at https://localhost:${server.port}`);
