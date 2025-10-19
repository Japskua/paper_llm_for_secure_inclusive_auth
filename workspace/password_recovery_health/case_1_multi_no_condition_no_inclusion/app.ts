/**
 * app.ts - Single-file Bun HTTPS server + SPA for Password Recovery System
 * Run: bun app.ts (Bun 1.3.0)
 *
 * Notes:
 * - All server and client code is contained in this single file.
 * - Uses HTTPS with TLS certs at certs/cert.pem and certs/key.pem.
 * - Implements CSRF, rate limiting, MFA, password reset with secure tokens, and secure headers.
 * - Simulated "delivery" (MFA codes and reset links) via console.log mirrored into on-page "Logs".
 *
 * Security Requirements mapping (inline comments reference sections):
 * - (1) Broken Access Control: CSRF token per session; sensitive POSTs require X-CSRF-Token; access control checks.
 * - (1) Broken Access Control — user enumeration mitigation: reset endpoints return uniform responses, decoy tokens/handles.
 * - (2) Injection (XSS): Strict CSP with no inline scripts; Trusted Types enforced; no innerHTML; all text set via textContent.
 * - (3) Security Misconfiguration: HTTPS + HSTS; CSP; X-Frame-Options; Referrer-Policy; Permissions-Policy; no stack traces to client.
 * - (4) Identification & Authentication Failures: Passwords hashed with Argon2id; MFA; strong password policy; throttling and rate limiting.
 * - (5) SSRF & Social Engineering: No external calls; connects only to self; shows safe-auth practices notice; no open redirects.
 */

const TLS_CERT_PATH = "certs/cert.pem";
const TLS_KEY_PATH = "certs/key.pem";

// ---- Constants for deterministic, reusable configuration (Acceptance: declared once) ----
const MFA_LIFETIME_MS = 5 * 60 * 1000; // 5 min MFA code
const RESET_TOKEN_TTL_MS = 10 * 60 * 1000; // 10 min reset tokens
const RESET_HANDLE_TTL_MS = 10 * 60 * 1000; // 10 min reset handle
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 min rate window
const RATE_LIMIT_MAX_ATTEMPTS = 5; // 5 attempts per window
const COOKIE_NAME = "sid";
const FIXED_DELAY_MS = 320; // ~300ms uniform artificial delay for reset endpoints (Req 1: enumeration mitigation)

// ---- In-memory stores (no persistence) ----
type Session = {
    id: string;
    csrfToken: string;
    createdAt: number;
    authenticatedUserId?: string;
    mfaPending?: { userId: string; code: string; expiresAt: number };
    rateLimits: Map<string, { windowStart: number; count: number }>;
    acceptedPrivacyAt?: number;
};
const sessions = new Map<string, Session>();

type User = {
    id: string;
    email: string;
    passwordHash: string;
    mfaSecret: string; // for realism only; we simulate delivery
};
const users = new Map<string, User>();

type ResetToken = {
    token: string;
    userId?: string; // absent for decoy
    decoy: boolean;
    expiresAt: number;
    used: boolean;
};
const resetTokens = new Map<string, ResetToken>();

type ResetHandle = {
    handle: string;
    userId?: string; // absent for decoy
    decoy: boolean;
    expiresAt: number;
};
const resetHandles = new Map<string, ResetHandle>();

// ---- Utilities ----
function b64url(buf: Uint8Array): string {
    // Convert to base64url
    let bin = "";
    for (const b of buf) bin += String.fromCharCode(b);
    return btoa(bin)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}
function randomId(bytes = 16): string {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return b64url(arr);
}

function parseCookies(header: string | null): Record<string, string> {
    const out: Record<string, string> = {};
    if (!header) return out;
    const parts = header.split(";").map((s) => s.trim());
    for (const p of parts) {
        const idx = p.indexOf("=");
        if (idx > -1) {
            const k = p.slice(0, idx).trim();
            const v = p.slice(idx + 1).trim();
            if (!(k in out)) out[k] = decodeURIComponent(v);
        }
    }
    return out;
}

function cookieHeaderForSession(session: Session): string {
    // (1) Broken Access Control: Secure cookie settings (HttpOnly, Secure, SameSite=Strict)
    return `${COOKIE_NAME}=${encodeURIComponent(
        session.id
    )}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

// Always attach strict security headers
// (2) Injection (XSS) + (3) Security Misconfiguration: CSP forbids inline scripts; enables Trusted Types; strong defaults.
function secureHeaders(styleNonce: string, isHTML = false): Headers {
    const h = new Headers();
    h.set("Referrer-Policy", "no-referrer");
    h.set("X-Frame-Options", "DENY");
    h.set("X-Content-Type-Options", "nosniff");
    h.set(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    );
    h.set(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload"
    );
    const csp = [
        `default-src 'self'`,
        `base-uri 'none'`,
        `object-src 'none'`,
        `frame-ancestors 'none'`,
        `form-action 'self'`,
        `connect-src 'self'`,
        `img-src 'self' data:`,
        `font-src 'self'`,
        // No inline scripts; only same-origin external scripts are allowed.
        `script-src 'self'`,
        // Enforce Trusted Types to harden against DOM XSS sinks.
        `require-trusted-types-for 'script'`,
        `trusted-types default`,
        // Style can remain inline but requires a nonce.
        `style-src 'self' 'nonce-${styleNonce}'`
    ].join("; ");
    h.set("Content-Security-Policy", csp);
    if (isHTML) h.set("Content-Type", "text/html; charset=utf-8");
    return h;
}

function getOrigin(urlStr: string): string {
    const u = new URL(urlStr);
    return `${u.protocol}//${u.host}`;
}

// Session management
function createSession(): Session {
    const s: Session = {
        id: randomId(24),
        csrfToken: randomId(24), // (1) CSRF unique per session
        createdAt: Date.now(),
        rateLimits: new Map()
    };
    sessions.set(s.id, s);
    return s;
}

function getSessionFromRequest(req: Request): Session | undefined {
    const cookies = parseCookies(req.headers.get("cookie"));
    const sid = cookies[COOKIE_NAME];
    if (!sid) return undefined;
    const s = sessions.get(sid);
    return s;
}

function requireSessionForPost(req: Request): Session | Response {
    const s = getSessionFromRequest(req);
    if (!s) {
        return json({ ok: false, message: "Invalid session" }, 403);
    }
    return s;
}

function verifyCsrf(req: Request, session: Session): Response | undefined {
    const token = req.headers.get("x-csrf-token");
    if (!token || token !== session.csrfToken) {
        // (1) Broken Access Control: deny missing/invalid CSRF
        return json({ ok: false, message: "Forbidden (CSRF)" }, 403);
    }
    return undefined;
}

// Rate limiting (4. Identification & Authentication Failures - throttling)
function checkRate(
    session: Session,
    key: string
): { ok: true } | { ok: false; retryAfter: number } {
    const now = Date.now();
    let rl = session.rateLimits.get(key);
    if (!rl || now - rl.windowStart > RATE_LIMIT_WINDOW_MS) {
        rl = { windowStart: now, count: 0 };
    }
    rl.count += 1;
    session.rateLimits.set(key, rl);
    if (rl.count > RATE_LIMIT_MAX_ATTEMPTS) {
        const retryAfter = Math.ceil(
            (rl.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000
        );
        return { ok: false, retryAfter: Math.max(1, retryAfter) };
    }
    return { ok: true };
}

function rateLimitedResponse(retryAfter: number): Response {
    const h = new Headers({ "Retry-After": String(retryAfter) });
    return json(
        { ok: false, message: "Too many attempts. Please try again later." },
        429,
        h
    );
}

function json(body: any, status = 200, extraHeaders?: Headers): Response {
    const h = new Headers(extraHeaders || undefined);
    h.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify(body), { status, headers: h });
}

function genericMessage(): string {
    // Generic error/success message without enumeration (4. Identification & Authentication Failures)
    return "If the account exists, we have sent instructions.";
}

// ---- Seed demo user with hashed password and MFA secret (4. Identification & Authentication) ----
const DEMO_USER_EMAIL = "helena@example.test";
const DEMO_USER_ID = "user-helena";
// Use a strong initial password; but we never reveal plaintext; only store hash
const INITIAL_PASSWORD = "HeleNA!2024-Strong"; // only used to generate the hash at startup
const PASSWORD_HASH = await Bun.password.hash(INITIAL_PASSWORD, {
    algorithm: "argon2id"
});
users.set(DEMO_USER_ID, {
    id: DEMO_USER_ID,
    email: DEMO_USER_EMAIL,
    passwordHash: PASSWORD_HASH,
    mfaSecret: "MFA-LOCAL-SECRET"
});

// ---- Client JS rendering (served via /app.js) ----
// (2) Injection (XSS) & (3) Security Misconfiguration: move to external JS, no inline scripts; TT policy created in client.
function renderClientJS(session: Session, origin: string): string {
    const csrf = session.csrfToken;
    return `
// SPA Client Script (external). Security: no inline script, Trusted Types enforced by CSP.
// (2) XSS hardening: create minimal Trusted Types policy named 'default' to satisfy 'trusted-types default' CSP.
(function(){
  'use strict';
  try {
    if (window.trustedTypes) {
      // Some browsers don't expose getPolicyNames; just attempt to create.
      window.trustedTypes.createPolicy('default', {
        createHTML: (s) => s,
        createScript: (s) => s,
        createScriptURL: (s) => s
      });
    }
  } catch (e) {
    // If policy already exists or TT unsupported, ignore.
  }

  // (1) CSRF: Provided per-session token embedded by server
  const CSRF_TOKEN = ${JSON.stringify(csrf)};
  const ORIGIN = ${JSON.stringify(origin)};

  // Mirror console.log to on-page logs panel (requirements: log delivery to browser console and visible UI)
  const logsEl = document.getElementById('logs');
  const originalLog = console.log.bind(console);
  console.log = function(...args){
    try {
      const line = args.map(x => {
        if (typeof x === 'string') return x;
        try { return JSON.stringify(x); } catch { return String(x); }
      }).join(' ');
      const ts = new Date().toISOString();
      const entry = document.createElement('div');
      entry.textContent = '[' + ts + '] ' + line;
      logsEl.appendChild(entry);
      logsEl.appendChild(document.createTextNode('\\n'));
      logsEl.scrollTop = logsEl.scrollHeight;
    } catch(e){}
    return originalLog(...args);
  };

  // Basic state
  const state = {
    mfaCodeFromServer: null,
    resetTokenFromServer: null,
    resetLinkFromServer: null,
    resetHandle: null,
    loggedIn: false,
    acceptedPrivacyAt: null
  };

  // DOM helpers: create elements safely and set text via textContent (no innerHTML to avoid XSS)
  function el(tag, attrs, text){
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  function btn(label, className){
    const b = el('button', className ? { class: className } : null, label);
    return b;
  }

  function row(children){
    const r = el('div', { class: 'row' });
    children.forEach(ch => r.appendChild(ch));
    return r;
  }

  function info(text, cls){
    return el('p', { class: cls || 'hint' }, text);
  }

  function formField(labelText, type, name, value){
    const w = document.createElement('div');
    const lab = el('label', { for: name }, labelText);
    const inp = el('input', { type, name, id: name, autocomplete: 'off' });
    if (value != null) inp.value = value;
    w.appendChild(lab);
    w.appendChild(inp);
    return { wrapper: w, input: inp };
  }

  function copyable(label, value){
    const p = el('p');
    const strong = el('strong', null, label + ': ');
    const code = el('span', { class: 'copy' }, value);
    const copyBtn = btn('Copy', 'secondary');
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(value).then(() => {
        console.log('Copied to clipboard:', label);
      });
    });
    p.appendChild(strong);
    p.appendChild(code);
    p.appendChild(el('span', null, ' '));
    p.appendChild(copyBtn);
    return p;
  }

  // Networking helper (always same-origin; includes CSRF header)
  async function api(path, body){
    const res = await fetch(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF_TOKEN
      },
      body: JSON.stringify(body || {})
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok) {
      const msg = data && data.message ? data.message : ('Request failed: ' + res.status);
      throw new Error(msg);
    }
    return data;
  }

  // Views
  const app = document.getElementById('app');

  function renderLogin(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Login'));
    const f1 = formField('Email', 'text', 'email', '');
    const f2 = formField('Password', 'password', 'password', '');
    const submit = btn('Sign in');
    const forgot = btn('Forgot Password', 'link');
    forgot.addEventListener('click', (e) => {
      e.preventDefault();
      location.hash = '#/forgot';
    });

    const msg = info('Enter your credentials. After successful password validation, an MFA code will be required.', 'hint');
    app.appendChild(f1.wrapper);
    app.appendChild(f2.wrapper);
    app.appendChild(row([submit, forgot]));
    app.appendChild(msg);

    submit.addEventListener('click', async () => {
      try {
        const email = f1.input.value || '';
        const password = f2.input.value || '';
        const res = await api('/api/login', { identifier: email, password });
        if (res && res.mfa_required) {
          state.mfaCodeFromServer = res.code;
          console.log('MFA code (simulated delivery):', res.code);
          location.hash = '#/mfa';
        } else if (res && res.ok === false) {
          app.appendChild(info(res.message || 'Invalid credentials', 'error'));
        } else {
          console.log('Login response:', res);
        }
      } catch (e) {
        console.log('Login error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });
  }

  function renderMFA(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Multi‑Factor Authentication'));
    app.appendChild(info('Enter the one-time code sent via secure channel (simulated below).', 'hint'));
    if (state.mfaCodeFromServer) {
      app.appendChild(copyable('MFA Code', state.mfaCodeFromServer));
    }
    const f = formField('Code', 'text', 'code', state.mfaCodeFromServer || '');
    const submit = btn('Verify');
    app.appendChild(f.wrapper);
    app.appendChild(submit);

    submit.addEventListener('click', async () => {
      try {
        const code = f.input.value || '';
        const res = await api('/api/verify-mfa', { code });
        if (res && res.ok) {
          state.loggedIn = true;
          console.log('MFA verified. Logged in.');
          location.hash = '#/privacy';
        } else {
          app.appendChild(info('Invalid or expired code.', 'error'));
        }
      } catch (e) {
        console.log('MFA verify error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });
  }

  function renderForgot(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Request Password Reset'));
    // (1) Broken Access Control — user enumeration mitigation: UI & client logs do not branch on account existence.
    app.appendChild(info('Enter your email. If the account exists, instructions will be provided.', 'hint'));
    const f = formField('Email', 'text', 'identifier', '');
    const submit = btn('Request reset');
    app.appendChild(f.wrapper);
    app.appendChild(submit);

    submit.addEventListener('click', async () => {
      try {
        const identifier = f.input.value || '';
        const res = await api('/api/request-reset', { identifier });
        console.log('If the account exists, a reset has been initiated.');
        // Always show the token & link returned by server (real or decoy)
        // (1) Enumeration mitigation: responses are uniform across existence states.
        if (res && res.token) {
          state.resetTokenFromServer = res.token;
          state.resetLinkFromServer = res.link;
          console.log('Password reset token (simulated delivery):', res.token);
          console.log('Password reset link (simulated delivery):', res.link);
        }
        location.hash = '#/verify';
      } catch (e) {
        console.log('Reset request error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });
  }

  function renderVerify(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Verify Reset Token'));
    if (state.resetTokenFromServer) {
      app.appendChild(copyable('Reset Token', state.resetTokenFromServer));
    }
    if (state.resetLinkFromServer) {
      const p = document.createElement('p');
      const strong = el('strong', null, 'Reset Link: ');
      const code = el('span', { class: 'copy' }, state.resetLinkFromServer);
      const copyBtn = btn('Copy', 'secondary');
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(state.resetLinkFromServer).then(() => {
          console.log('Copied reset link to clipboard');
        });
      });
      p.appendChild(strong);
      p.appendChild(code);
      p.appendChild(el('span', null, ' '));
      p.appendChild(copyBtn);
      app.appendChild(p);
    }
    const f = formField('Enter token manually', 'text', 'token', state.resetTokenFromServer || '');
    const submit = btn('Verify token');
    app.appendChild(f.wrapper);
    app.appendChild(submit);

    submit.addEventListener('click', async () => {
      const token = f.input.value || '';
      try {
        const res = await api('/api/verify-reset', { token });
        if (res && res.handle) {
          state.resetHandle = res.handle;
          console.log('Reset token accepted. Received handle:', res.handle);
          location.hash = '#/reset';
        } else {
          app.appendChild(info('Invalid or expired token.', 'error'));
        }
      } catch (e) {
        console.log('Verify reset error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });
  }

  function renderSetNewPassword(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Set New Password'));
    if (!state.resetHandle) {
      app.appendChild(info('No active reset handle. Go to Forgot Password first.', 'error'));
      const back = btn('Forgot Password', 'link');
      back.addEventListener('click', (e)=>{ e.preventDefault(); location.hash = '#/forgot'; });
      app.appendChild(back);
      return;
    }
    app.appendChild(info('Password policy: at least 12 characters, including uppercase, lowercase, number, and symbol.', 'hint'));
    const f1 = formField('New password', 'password', 'newpass', '');
    const f2 = formField('Confirm password', 'password', 'confirm', '');
    const submit = btn('Update password');
    app.appendChild(f1.wrapper);
    app.appendChild(f2.wrapper);
    app.appendChild(submit);

    submit.addEventListener('click', async () => {
      const p1 = f1.input.value || '';
      const p2 = f2.input.value || '';
      if (p1 !== p2) {
        app.appendChild(info('Passwords do not match.', 'error'));
        return;
      }
      try {
        const res = await api('/api/set-new-password', { handle: state.resetHandle, newPassword: p1 });
        if (res && res.ok) {
          console.log('Password updated successfully. Please login again.');
          state.resetHandle = null;
          location.hash = '#/login';
        } else {
          app.appendChild(info((res && res.message) || 'Password update failed.', 'error'));
        }
      } catch (e) {
        console.log('Set new password error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });
  }

  function renderPrivacy(){
    app.replaceChildren();
    app.appendChild(el('h2', null, 'Updated Privacy Terms'));
    const text = el('p', null, 'To proceed with appointments, please accept the updated privacy statement.');
    app.appendChild(text);
    if (!state.loggedIn) {
      app.appendChild(info('You must login first to accept.', 'error'));
      const go = btn('Go to Login', 'link');
      go.addEventListener('click', (e)=>{ e.preventDefault(); location.hash = '#/login'; });
      app.appendChild(go);
      return;
    }
    const acceptBtn = btn('Accept Privacy Statement');
    if (state.acceptedPrivacyAt) {
      app.appendChild(info('You accepted these terms on ' + new Date(state.acceptedPrivacyAt).toLocaleString(), 'success'));
    } else {
      app.appendChild(acceptBtn);
    }
    acceptBtn.addEventListener('click', async () => {
      try {
        const res = await api('/api/accept-privacy', {});
        if (res && res.ok) {
          state.acceptedPrivacyAt = Date.now();
          console.log('Privacy terms accepted.');
          renderPrivacy();
        } else {
          app.appendChild(info('Failed to accept terms.', 'error'));
        }
      } catch (e) {
        console.log('Accept privacy error:', String(e.message || e));
        app.appendChild(info(String(e.message || e), 'error'));
      }
    });

    const logout = btn('Logout', 'secondary');
    logout.addEventListener('click', async () => {
      try {
        await api('/api/logout', {});
        console.log('Logged out.');
        state.loggedIn = false;
        state.acceptedPrivacyAt = null;
        location.hash = '#/login';
      } catch (e) {
        console.log('Logout error:', String(e.message || e));
      }
    });
    app.appendChild(el('hr'));
    app.appendChild(row([logout]));
  }

  // Router
  function renderRoute(){
    const hash = location.hash || '#/login';
    switch (hash) {
      case '#/login': renderLogin(); break;
      case '#/mfa': renderMFA(); break;
      case '#/forgot': renderForgot(); break;
      case '#/verify': renderVerify(); break;
      case '#/reset': renderSetNewPassword(); break;
      case '#/privacy': renderPrivacy(); break;
      default: renderLogin(); break;
    }
  }
  window.addEventListener('hashchange', renderRoute);

  // If the page was opened with ?token=... support auto-verification attempt
  (async function handleQueryToken(){
    const url = new URL(location.href);
    const token = url.searchParams.get('token');
    if (token) {
      try {
        console.log('Found reset token in URL. Verifying...');
        const res = await api('/api/verify-reset', { token });
        if (res && res.handle) {
          state.resetHandle = res.handle;
          console.log('Reset token verified from URL. Handle:', res.handle);
          // Remove the query param to avoid reuse/leak
          url.searchParams.delete('token');
          history.replaceState(null, '', url.toString());
          location.hash = '#/reset';
        }
      } catch (e) {
        console.log('Auto-verify token error:', String(e.message || e));
      }
    }
  })();

  renderRoute();
})();
`;
}

// ---- HTML rendering ----
function renderHTML(
    session: Session,
    styleNonce: string,
    origin: string
): string {
    // Inline HTML+CSS; all client JS loaded from /app.js (no inline scripts).
    const safeTitle = "Hospital Account Portal — Password Recovery Demo";
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${safeTitle}</title>
  <style nonce="${styleNonce}">
    :root { color-scheme: light dark; }
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f7f7f9; color:#222; }
    header { background:#0d3b66; color:#fff; padding: 1rem 1.25rem; }
    header h1 { margin:0; font-size:1.2rem; }
    main { display:flex; gap:1rem; padding:1rem; max-width:1100px; margin: 0 auto; }
    .card { background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:1rem; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
    #app { flex: 1; min-height: 60vh; }
    #sidebar { width: 340px; display:flex; flex-direction:column; gap:.75rem; }
    label { display:block; margin:.25rem 0 .2rem; font-weight:600; }
    input[type="text"], input[type="password"] { width:100%; padding:.5rem .6rem; border:1px solid #cbd5e1; border-radius:6px; font-size:1rem; }
    button { background:#0d3b66; color:#fff; border:none; border-radius:6px; padding:.6rem .9rem; font-size:1rem; cursor:pointer; }
    button.secondary { background:#334155; }
    button.link { background:transparent; color:#0d3b66; text-decoration:underline; padding:0; }
    .row { display:flex; gap:.5rem; align-items:center; }
    .hint { font-size:.9rem; color:#475569; }
    .error { color:#b91c1c; font-weight:600; }
    .success { color:#065f46; font-weight:600; }
    nav a { color:#fff; margin-right:1rem; text-decoration:underline; }
    .hidden { display:none !important; }
    pre.logs { margin:0; padding:.75rem; background:#0b1020; color:#d1d5db; min-height:180px; max-height:320px; overflow:auto; border-radius:6px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .muted { color:#64748b; font-size:.9rem; }
    .copy { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#f1f5f9; padding:.25rem .4rem; border-radius:4px; border:1px solid #e5e7eb; }
    ul { margin:.25rem 0 .75rem 1.25rem; }
  </style>
</head>
<body>
  <header>
    <h1>${safeTitle}</h1>
    <nav>
      <a href="#/login">Login</a>
      <a href="#/forgot">Forgot Password</a>
      <a href="#/privacy">Privacy Acceptance</a>
    </nav>
  </header>
  <main>
    <section id="app" class="card" aria-live="polite"></section>
    <aside id="sidebar">
      <div class="card">
        <h2>Logs</h2>
        <p class="muted">All delivery + server-simulated messages also appear here.</p>
        <pre id="logs" class="logs" aria-live="polite"></pre>
      </div>
      <div class="card">
        <h2>Security Notes</h2>
        <p class="hint">This demo enforces HTTPS, CSRF protection, strict CSP, Trusted Types, secure cookies, and rate limiting.</p>
        <p class="hint">Safe-auth tip: never share passwords or codes by email/SMS; only use links from the official domain.</p>
      </div>
    </aside>
  </main>

  <!-- Client JS is served as a separate file to comply with CSP no-inline-scripts (Req 2,3). -->
  <script src="/app.js"></script>
</body>
</html>`;
}

// ---- API Handlers ----

async function handleLogin(req: Request, session: Session): Promise<Response> {
    const rl = checkRate(session, "login");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    let body: any = {};
    try {
        body = await req.json();
    } catch {}
    const identifier = String(body?.identifier || "");
    const password = String(body?.password || "");

    // No user enumeration: search by email case-insensitively; generic errors
    const user = Array.from(users.values()).find(
        (u) => u.email.toLowerCase() === identifier.toLowerCase()
    );
    if (!user) {
        // Generic response
        return json({ ok: false, message: "Invalid credentials" }, 200);
    }
    const passOk = await Bun.password.verify(password, user.passwordHash);
    if (!passOk) {
        return json({ ok: false, message: "Invalid credentials" }, 200);
    }

    // Generate one-time MFA code (random 6 digits), short-lived (4. Identification)
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    session.mfaPending = {
        userId: user.id,
        code,
        expiresAt: Date.now() + MFA_LIFETIME_MS
    };

    // mfa_required and code for delivery simulation
    return json({ ok: true, mfa_required: true, code });
}

async function handleVerifyMFA(
    req: Request,
    session: Session
): Promise<Response> {
    const rl = checkRate(session, "verify-mfa");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    let body: any = {};
    try {
        body = await req.json();
    } catch {}
    const code = String(body?.code || "");
    const pending = session.mfaPending;
    if (!pending || Date.now() > pending.expiresAt || pending.code !== code) {
        return json({ ok: false, message: "Invalid or expired code" }, 400);
    }
    session.authenticatedUserId = pending.userId;
    session.mfaPending = undefined;
    return json({ ok: true });
}

// (1) Broken Access Control — user enumeration mitigation:
// /api/request-reset returns uniform JSON fields regardless of identifier existence.
// For unknown identifiers, a decoy token & link are generated with identical length/format/TTL.
async function handleRequestReset(
    req: Request,
    session: Session
): Promise<Response> {
    const rl = checkRate(session, "request-reset");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    // Uniform artificial delay to equalize timing (real vs decoy)
    await Bun.sleep(FIXED_DELAY_MS);

    let body: any = {};
    try {
        body = await req.json();
    } catch {}
    const identifier = String(body?.identifier || "");

    const user = Array.from(users.values()).find(
        (u) => u.email.toLowerCase() === identifier.toLowerCase()
    );

    // Create a token (real or decoy) with identical shape and TTL
    const token = randomId(32);
    const record: ResetToken = {
        token,
        userId: user ? user.id : undefined,
        decoy: !user,
        expiresAt: Date.now() + RESET_TOKEN_TTL_MS,
        used: false
    };
    resetTokens.set(token, record);

    // Build absolute link
    const origin = getOrigin(req.url);
    const link = `${origin}/?token=${encodeURIComponent(token)}#`;

    // Always return same keys and status to avoid user enumeration
    // Keys: ok, token, link, message
    return json({ ok: true, token, link, message: genericMessage() });
}

// (1) Broken Access Control — user enumeration mitigation:
// /api/verify-reset accepts both real & decoy tokens and ALWAYS returns {ok:true, handle, expiresAt} (200).
// Tokens are marked used. Unknown/expired tokens yield a decoy handle.
async function handleVerifyReset(
    req: Request,
    session: Session
): Promise<Response> {
    const rl = checkRate(session, "verify-reset");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    // Uniform artificial delay
    await Bun.sleep(FIXED_DELAY_MS);

    let body: any = {};
    try {
        body = await req.json();
    } catch {}
    const token = String(body?.token || "");

    const rec = resetTokens.get(token);
    let decoy = true;
    let userId: string | undefined = undefined;

    if (rec && !rec.used && Date.now() <= rec.expiresAt) {
        // Valid token (real or decoy)
        rec.used = true; // single-use semantics
        resetTokens.set(token, rec);
        decoy = rec.decoy;
        userId = rec.userId;
    } else {
        // Unknown/expired/used -> proceed with decoy handle, no leaks (uniform response)
        decoy = true;
        userId = undefined;
    }

    const handle = randomId(24);
    const expiresAt = Date.now() + RESET_HANDLE_TTL_MS;
    resetHandles.set(handle, { handle, userId, decoy, expiresAt });

    return json({ ok: true, handle, expiresAt });
}

function validateStrongPassword(pw: string): string | null {
    if (pw.length < 12) return "Password must be at least 12 characters.";
    if (!/[a-z]/.test(pw)) return "Password must include a lowercase letter.";
    if (!/[A-Z]/.test(pw)) return "Password must include an uppercase letter.";
    if (!/[0-9]/.test(pw)) return "Password must include a number.";
    if (!/[^A-Za-z0-9]/.test(pw)) return "Password must include a symbol.";
    return null;
}

// (1) Broken Access Control — user enumeration mitigation:
// /api/set-new-password: For invalid/expired/decoy handles, return generic 200 { ok: true }.
// For a real, unexpired handle with weak password, return HTTP 400 { ok:false, message } and invalidate the handle.
// For a real, unexpired handle with strong password, update and return 200 { ok:true }.
async function handleSetNewPassword(
    req: Request,
    session: Session
): Promise<Response> {
    const rl = checkRate(session, "set-new-password");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    // Uniform artificial delay
    await Bun.sleep(FIXED_DELAY_MS);

    let body: any = {};
    try {
        body = await req.json();
    } catch {}
    const handle = String(body?.handle || "");
    const newPassword = String(body?.newPassword || "");

    const h = resetHandles.get(handle);

    // Missing or expired handle -> generic success; cleanup if present
    if (!h || Date.now() > h.expiresAt) {
        if (h) resetHandles.delete(handle);
        return json({
            ok: true,
            message: "If the account exists, it has been updated."
        });
    }

    const isReal = !h.decoy && Boolean(h.userId) && users.has(h.userId!);

    if (!isReal) {
        // Decoy handle -> generic success; invalidate handle
        resetHandles.delete(handle);
        return json({
            ok: true,
            message: "If the account exists, it has been updated."
        });
    }

    // Real handle: enforce password policy with explicit 400 on failure
    const policyError = validateStrongPassword(newPassword);
    if (policyError) {
        resetHandles.delete(handle); // invalidate regardless
        return json({ ok: false, message: policyError }, 400);
    }

    // Update password for real user
    const user = users.get(h.userId!);
    if (user) {
        const hash = await Bun.password.hash(newPassword, {
            algorithm: "argon2id"
        });
        user.passwordHash = hash;
        users.set(user.id, user);

        // Invalidate all outstanding reset tokens for this user (defense-in-depth)
        for (const [tok, rec] of resetTokens) {
            if (rec.userId === user.id) {
                rec.used = true;
                resetTokens.set(tok, rec);
            }
        }
        // Invalidate any logged-in sessions for this user (log them out)
        for (const s of sessions.values()) {
            if (s.authenticatedUserId === user.id) {
                s.authenticatedUserId = undefined;
                s.mfaPending = undefined;
            }
        }
    }

    // Invalidate handle and return generic success
    resetHandles.delete(handle);
    return json({
        ok: true,
        message: "If the account exists, it has been updated."
    });
}

async function handleLogout(req: Request, session: Session): Promise<Response> {
    const rl = checkRate(session, "logout");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    session.authenticatedUserId = undefined;
    session.mfaPending = undefined;
    return json({ ok: true });
}

async function handleAcceptPrivacy(
    req: Request,
    session: Session
): Promise<Response> {
    const rl = checkRate(session, "accept-privacy");
    if (!rl.ok) return rateLimitedResponse(rl.retryAfter);

    const err = verifyCsrf(req, session);
    if (err) return err;

    if (!session.authenticatedUserId) {
        return json({ ok: false, message: "Unauthorized" }, 401);
    }
    session.acceptedPrivacyAt = Date.now();
    return json({ ok: true, acceptedAt: session.acceptedPrivacyAt });
}

// ---- HTTPS Server ----
const tls = {
    cert: Bun.file(TLS_CERT_PATH),
    key: Bun.file(TLS_KEY_PATH)
};

const server = Bun.serve({
    tls,
    port: 8443,
    async fetch(req: Request) {
        const url = new URL(req.url);
        const path = url.pathname;
        const method = req.method.toUpperCase();
        const origin = getOrigin(req.url);

        // JS route must be handled explicitly to comply with CSP no-inline-scripts
        if (method === "GET" && path === "/app.js") {
            let session = getSessionFromRequest(req);
            if (!session) session = createSession();
            const js = renderClientJS(session, origin);
            const styleNonce = randomId(16);
            const headers = secureHeaders(styleNonce, false);
            headers.set(
                "Content-Type",
                "application/javascript; charset=utf-8"
            );
            headers.set("Set-Cookie", cookieHeaderForSession(session));
            return new Response(js, { status: 200, headers });
        }

        // Create or get session for other GET requests (first GET sets cookie and CSRF)
        let session = getSessionFromRequest(req);
        if (method === "GET") {
            if (!session) {
                session = createSession();
            }
            // Serve SPA HTML for all other GET routes
            const styleNonce = randomId(16);
            const headers = secureHeaders(styleNonce, true);
            headers.set("Set-Cookie", cookieHeaderForSession(session));
            const body = renderHTML(session, styleNonce, origin);
            return new Response(body, { status: 200, headers });
        }

        // POST endpoints require an existing session & CSRF (1. Broken Access Control)
        const sessOrErr = requireSessionForPost(req);
        if (sessOrErr instanceof Response) {
            // Attach security headers also for errors
            const styleNonce = randomId(12);
            const h = secureHeaders(styleNonce, false);
            // Copy existing headers
            sessOrErr.headers.forEach((v, k) => h.set(k, v));
            return new Response(await sessOrErr.text(), {
                status: sessOrErr.status,
                headers: h
            });
        }
        session = sessOrErr;

        // Route handling for API (no external network calls)
        let res: Response | null = null;
        try {
            if (method === "POST" && path === "/api/login") {
                res = await handleLogin(req, session);
            } else if (method === "POST" && path === "/api/verify-mfa") {
                res = await handleVerifyMFA(req, session);
            } else if (method === "POST" && path === "/api/request-reset") {
                res = await handleRequestReset(req, session);
            } else if (method === "POST" && path === "/api/verify-reset") {
                res = await handleVerifyReset(req, session);
            } else if (method === "POST" && path === "/api/set-new-password") {
                res = await handleSetNewPassword(req, session);
            } else if (method === "POST" && path === "/api/logout") {
                res = await handleLogout(req, session);
            } else if (method === "POST" && path === "/api/accept-privacy") {
                res = await handleAcceptPrivacy(req, session);
            } else {
                res = json({ ok: false, message: "Not found" }, 404);
            }
        } catch (_e) {
            // Do not leak stack traces (3. Security Misconfiguration)
            res = json({ ok: false, message: "Server error" }, 500);
        }

        // Attach security headers to all responses
        const styleNonce = randomId(12);
        const h = secureHeaders(styleNonce, false);
        // Copy existing headers
        res.headers.forEach((v, k) => h.set(k, v));
        return new Response(await res.text(), {
            status: res.status,
            headers: h
        });
    }
});

console.log(
    `HTTPS server running on https://localhost:${server.port} (TLS enabled)`
);
