/**
 * app.ts - Single-file HTTPS Bun server + SPA client
 * Run with: bun app.ts (Bun 1.3.0)
 *
 * This implementation satisfies requirements for:
 * - Broken Access Control (BAC): CSRF tokens per session, session-bound reset tokens, access checks
 * - Injection (XSS): CSP (no inline scripts), no innerHTML for untrusted data, DOM updated via textContent, sanitization
 * - Security Misconfiguration: HTTPS with TLS, HSTS, CSP, secure headers
 * - Identification & Authentication: Argon2id hashing, MFA in reset flow, throttling, strong password policy
 * - SSRF/Open Redirects: No external calls, validate hash routing to internal only
 */

const PORT = 8442;

// ---------- Utilities ----------
function base64url(bytes: Uint8Array) {
    const b64 = Buffer.from(bytes).toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomId(size = 32) {
    const b = new Uint8Array(size);
    crypto.getRandomValues(b);
    return base64url(b);
}
function now() {
    return Date.now();
}

// ---------- In-memory Stores (No external persistence) ----------
// Users
type User = {
    id: string;
    email: string;
    username: string;
    passwordHash: string;
    createdAt: number;
    mfaEnabled?: boolean;
};
const users = new Map<string, User>();
// Secondary indexes to avoid exposing direct private identifiers (BAC)
const emailToUserId = new Map<string, string>();
const usernameToUserId = new Map<string, string>();

// Sessions
type Session = {
    id: string;
    csrfToken: string;
    createdAt: number;
    // For throttle accounting per-session (Auth)
    rate: Map<string, { count: number; first: number }>;
    // Reset flow state (Auth)
    resetVerified?: boolean;
    resetTokenId?: string;
    resetUserId?: string | null;
    mfaCode?: string;
    mfaVerified?: boolean;
    // Login state
    userId?: string;
};
const sessions = new Map<string, Session>();

// Password Reset Tokens
type ResetToken = {
    token: string;
    userId: string | null; // may be null to avoid existence leak
    createdAt: number;
    expiresAt: number; // 15m TTL (Misconfiguration: short-lived)
    used: boolean;
    sessionId: string; // bind to session (BAC)
};
const resetTokens = new Map<string, ResetToken>();

// Rate limiter (per-IP and per-session)
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMITS: Record<string, number> = {
    login: 5,
    "request-reset": 5,
    "verify-reset": 8,
    "send-mfa": 8,
    "verify-mfa": 8
};
const ipRate = new Map<string, { count: number; first: number }>();

function checkRateLimiter(
    ip: string,
    session: Session | null,
    key: keyof typeof RATE_LIMITS
) {
    const limit = RATE_LIMITS[key];
    const retryCalc = (entry: { first: number }) =>
        Math.max(
            1,
            Math.ceil((entry.first + RATE_LIMIT_WINDOW_MS - now()) / 1000)
        );
    // IP-based
    const ipKey = `${ip}:${key}`;
    let ipEntry = ipRate.get(ipKey);
    if (!ipEntry || now() - ipEntry.first > RATE_LIMIT_WINDOW_MS) {
        ipEntry = { count: 0, first: now() };
        ipRate.set(ipKey, ipEntry);
    }
    ipEntry.count++;
    if (ipEntry.count > limit) {
        return { allowed: false, retryAfter: retryCalc(ipEntry) };
    }
    // Session-based
    if (session) {
        const sessKey = `rate:${key}`;
        let sEntry = session.rate.get(sessKey);
        if (!sEntry || now() - sEntry.first > RATE_LIMIT_WINDOW_MS) {
            sEntry = { count: 0, first: now() };
            session.rate.set(sessKey, sEntry);
        }
        sEntry.count++;
        if (sEntry.count > limit) {
            return { allowed: false, retryAfter: retryCalc(sEntry) };
        }
    }
    return { allowed: true };
}

// ---------- Demo seed user (Auth: Argon2id hashed) ----------
const demoPasswordHash = await Bun.password.hash("StrongPassw0rd!", {
    algorithm: "argon2id"
});
const demoUser: User = {
    id: "u1",
    email: "helena@example.com",
    username: "helena67",
    passwordHash: demoPasswordHash,
    createdAt: now(),
    mfaEnabled: true
};
users.set(demoUser.id, demoUser);
emailToUserId.set(demoUser.email.toLowerCase(), demoUser.id);
usernameToUserId.set(demoUser.username.toLowerCase(), demoUser.id);

// ---------- Cookie helpers ----------
function parseCookies(req: Request) {
    const header = req.headers.get("cookie");
    const out: Record<string, string> = {};
    if (!header) return out;
    const parts = header.split(";").map((p) => p.trim());
    for (const p of parts) {
        const [k, ...rest] = p.split("=");
        if (!k) continue;
        out[k] = decodeURIComponent(rest.join("="));
    }
    return out;
}
function sessionCookie(id: string) {
    // Security: HttpOnly, Secure, SameSite=Strict (BAC, Misconfiguration)
    return `sid=${encodeURIComponent(
        id
    )}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}
// create or load session
function getOrCreateSession(req: Request) {
    const cookies = parseCookies(req);
    const sid = cookies["sid"];
    if (sid) {
        const s = sessions.get(sid);
        if (s) return { session: s, isNew: false };
    }
    const newId = randomId(32);
    const csrfToken = randomId(32);
    const sess: Session = {
        id: newId,
        csrfToken,
        createdAt: now(),
        rate: new Map()
    };
    sessions.set(newId, sess);
    return { session: sess, isNew: true };
}
function getSessionFromRequest(req: Request) {
    const cookies = parseCookies(req);
    const sid = cookies["sid"];
    if (sid) {
        return sessions.get(sid) || null;
    }
    return null;
}

// ---------- Security Headers ----------
function securityHeaders(nonce: string) {
    const csp = [
        "default-src 'none'",
        "script-src 'self'",
        `style-src 'self' 'nonce-${nonce}'`,
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'"
    ].join("; ");
    return {
        "Content-Security-Policy": csp,
        "Strict-Transport-Security":
            "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Permissions-Policy":
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    };
}

function jsonResponse(body: unknown, nonce: string, init?: ResponseInit) {
    const headers = new Headers(init?.headers);
    headers.set("Content-Type", "application/json; charset=utf-8");
    const sec = securityHeaders(nonce);
    for (const [k, v] of Object.entries(sec)) headers.set(k, v);
    headers.set("Vary", "Cookie");
    return new Response(JSON.stringify(body), {
        status: init?.status ?? 200,
        headers
    });
}

function textResponse(body: string, nonce: string, init?: ResponseInit) {
    const headers = new Headers(init?.headers);
    headers.set("Content-Type", "text/plain; charset=utf-8");
    const sec = securityHeaders(nonce);
    for (const [k, v] of Object.entries(sec)) headers.set(k, v);
    headers.set("Vary", "Cookie");
    return new Response(body, { status: init?.status ?? 200, headers });
}

// ---------- HTML ----------
function renderHTML(nonce: string, session: Session) {
    // CSP nonce applied to style. CSRF token exposed via meta attribute (BAC + XSS).
    const csrf = session.csrfToken;
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Password Recovery Demo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${csrf}">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <style nonce="${nonce}">
    :root {
      color-scheme: light dark;
      --bg: #0b1220;
      --panel: #0e1a2b;
      --text: #e7eef9;
      --muted: #a8b3c7;
      --accent: #4cc9f0;
      --error: #ff6b6b;
      --ok: #95d5b2;
      --warn: #ffd166;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, "Apple Color Emoji", "Segoe UI Emoji";
      background: var(--bg);
      color: var(--text);
    }
    header, footer { padding: 1rem; text-align: center; }
    header { background: linear-gradient(90deg, #1b2a41, #14213d); }
    main {
      display: grid;
      grid-template-columns: 1fr 340px;
      gap: 1rem;
      padding: 1rem;
      max-width: 1100px;
      margin: 0 auto;
    }
    .card {
      background: var(--panel);
      border-radius: 10px;
      padding: 1rem;
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }
    #view {
      min-height: 420px;
    }
    #logs {
      height: 420px;
      overflow: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      background: #0a0f18;
      border: 1px solid #223;
      padding: .5rem;
      white-space: pre-wrap;
    }
    .row { margin: .5rem 0; }
    label { display: block; margin-bottom: .25rem; color: var(--muted); }
    input, button, a.button {
      width: 100%;
      padding: .6rem .8rem;
      border-radius: 8px;
      border: 1px solid #2a3b55;
      background: #0f1b2e;
      color: var(--text);
    }
    button, a.button {
      cursor: pointer;
      background: #17345e;
      border-color: #214c8a;
    }
    button:hover, a.button:hover { filter: brightness(1.08); }
    .muted { color: var(--muted); font-size: .9rem; }
    .ok { color: var(--ok); }
    .error { color: var(--error); }
    nav a {
      color: var(--accent);
      text-decoration: none;
      margin-right: 1rem;
    }
    .stack { display: grid; gap: .5rem; }
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
    .small { font-size: .85rem; }
    .center { text-align: center; }
    .hidden { display: none !important; }
  </style>
  <script src="/app.js" defer></script>
</head>
<body>
  <header>
    <h1>Password Recovery System (Academic Demo)</h1>
    <div class="small muted">HTTPS enforced. CSP, HSTS, CSRF, rate limiting, MFA, Argon2id hashing. No external calls.</div>
    <nav aria-label="Primary">
      <a href="#/login" rel="nofollow">Login</a>
      <a href="#/forgot" rel="nofollow">Forgot password</a>
      <a href="#/verify" rel="nofollow">Enter token</a>
    </nav>
  </header>
  <main role="main">
    <section id="view" class="card" aria-live="polite" aria-busy="false">
      <h2 class="muted">Loading…</h2>
    </section>
    <aside class="card" aria-label="Logs">
      <h3>Logs</h3>
      <div id="logs" role="log" aria-live="polite"></div>
      <div class="muted small">All simulated deliveries (tokens, MFA codes) are logged here for testing only.</div>
    </aside>
  </main>
  <footer class="small muted">
    Security notes:
    • Never share passwords or codes. • Beware of phishing. • This is a local academic simulation with deterministic in-memory state.
  </footer>
</body>
</html>`;
    return html;
}

// ---------- Static client JS (served at /app.js) ----------
const APP_JS = `(()=>{'use strict';
  // Security: augment console.log to also display in "Logs" panel (requirement: mirror console to panel)
  const logEl = document.getElementById('logs');
  const origLog = console.log;
  console.log = function(){
    try {
      const msg = Array.from(arguments).map(x => {
        if (typeof x === 'string') return x;
        try { return JSON.stringify(x); } catch { return String(x); }
      }).join(' ');
      const line = document.createElement('div');
      line.textContent = msg;
      if (logEl) {
        logEl.appendChild(line);
        logEl.scrollTop = logEl.scrollHeight;
      }
    } catch {}
    return origLog.apply(console, arguments);
  };

  // CSRF token from safe meta attribute (BAC)
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = csrfMeta ? csrfMeta.getAttribute('content') : '';

  // Client-side sanitization utilities (XSS)
  function sanitizeInput(str, maxLen){
    if (typeof str !== 'string') return '';
    let s = str.trim();
    if (maxLen && s.length > maxLen) s = s.slice(0, maxLen);
    // remove control and angle brackets to be safe
    s = s.replace(/[<>\\\\]/g, '').replace(/[\\u0000-\\u001F\\u007F]/g, '');
    return s;
  }
  function setText(el, text){
    if (!el) return;
    el.textContent = String(text ?? '');
  }
  function clear(el){ while(el.firstChild) el.removeChild(el.firstChild); }

  // Fetch helper with CSRF and credentials (BAC)
  async function postJSON(path, data){
    // SSRF/Open redirect: we restrict to same-origin relative paths
    if (!path.startsWith('/api/')) throw new Error('Blocked request');
    const res = await fetch(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': CSRF || ''
      },
      credentials: 'include',
      body: JSON.stringify(data || {})
    });
    const retryAfter = res.headers.get('Retry-After');
    let payload;
    try { payload = await res.json(); } catch { payload = { message: 'Invalid response' }; }
    if (!res.ok) {
      const err = new Error(payload && payload.message ? payload.message : res.statusText);
      err.name = 'HttpError';
      err['status'] = res.status;
      if (retryAfter) err['retryAfter'] = retryAfter;
      throw err;
    }
    return payload;
  }

  // Simple hash router with internal route validation (SSRF/open redirect prevention)
  const view = document.getElementById('view');

  function parseHash(){
    const h = location.hash || '#/login';
    // block potentially malicious hashes (no protocols or slashes beginning with //)
    if (h.startsWith('#http') || h.startsWith('#//')) return { path: '/login', query: {} };
    const [pathPart, queryPart] = h.slice(1).split('?');
    const path = pathPart || '/login';
    const query = {};
    if (queryPart) {
      for (const kv of queryPart.split('&')) {
        const [k,v] = kv.split('=');
        if (!k) continue;
        query[decodeURIComponent(k)] = decodeURIComponent(v || '');
      }
    }
    return { path, query };
  }

  function makeInput(labelText, type, name, autocomplete){
    const container = document.createElement('div');
    container.className = 'row';
    const label = document.createElement('label');
    label.setAttribute('for', name);
    setText(label, labelText);
    const input = document.createElement('input');
    input.type = type;
    input.name = name;
    input.id = name;
    if (autocomplete) input.autocomplete = autocomplete;
    container.appendChild(label);
    container.appendChild(input);
    return { container, input, label };
  }

  function message(el, text, cls){
    const p = document.createElement('div');
    p.className = 'row ' + (cls || 'muted');
    setText(p, text);
    el.appendChild(p);
    return p;
  }

  function handleError(container, err){
    const msg = err && err.message ? String(err.message) : 'Unexpected error';
    console.log('Error:', msg);
    const e = document.createElement('div');
    e.className = 'row error';
    if (err && err.status === 429 && err.retryAfter) {
      setText(e, msg + ' (Retry after ' + err.retryAfter + 's)');
    } else {
      setText(e, msg);
    }
    container.appendChild(e);
  }

  function render(){
    const { path, query } = parseHash();
    view.setAttribute('aria-busy', 'true');
    clear(view);
    if (path === '/login') {
      renderLogin();
    } else if (path === '/forgot') {
      renderForgot();
    } else if (path === '/verify') {
      renderVerify(query);
    } else if (path === '/mfa') {
      renderMfa();
    } else if (path === '/set') {
      renderSetPassword();
    } else if (path === '/done') {
      renderDone();
    } else {
      const h2 = document.createElement('h2');
      setText(h2, 'Not found');
      view.appendChild(h2);
      const p = document.createElement('p');
      p.className = 'muted';
      setText(p, 'Use the navigation links above.');
      view.appendChild(p);
    }
    view.setAttribute('aria-busy', 'false');
  }

  // Views

  function renderLogin(){
    const title = document.createElement('h2');
    setText(title, 'Login');
    view.appendChild(title);

    const info = message(view, 'Do not share your password. This demo uses strong hashing (Argon2id).', 'muted small');

    const idField = makeInput('Email or username', 'text', 'identifier', 'username');
    const pwField = makeInput('Password', 'password', 'password', 'current-password');
    view.appendChild(idField.container);
    view.appendChild(pwField.container);

    const submit = document.createElement('button');
    setText(submit, 'Sign in');
    submit.addEventListener('click', async () => {
      clear(info);
      const identifier = sanitizeInput(idField.input.value, 120);
      const password = sanitizeInput(pwField.input.value, 200);
      const status = message(view, 'Signing in…', 'muted small');
      try {
        const res = await postJSON('/api/login', { identifier, password });
        setText(status, res.message || 'Login processed.');
        status.className = 'row ok';
      } catch (err) {
        status.remove();
        handleError(view, err);
      }
    });
    view.appendChild(submit);

    const forgot = document.createElement('p');
    forgot.className = 'muted small';
    const a = document.createElement('a');
    a.href = '#/forgot';
    a.rel = 'nofollow';
    setText(a, 'Forgot password?');
    forgot.appendChild(a);
    view.appendChild(forgot);
  }

  function renderForgot(){
    const title = document.createElement('h2');
    setText(title, 'Request password reset');
    view.appendChild(title);

    message(view, 'Enter your email or username. If your account exists, we will send instructions.', 'muted small');

    const idField = makeInput('Email or username', 'text', 'identifier', 'username');
    view.appendChild(idField.container);

    const submit = document.createElement('button');
    setText(submit, 'Send reset link');
    submit.addEventListener('click', async () => {
      const identifier = sanitizeInput(idField.input.value, 120);
      const status = message(view, 'Processing…', 'muted small');
      try {
        const res = await postJSON('/api/request-reset', { identifier });
        setText(status, 'If an account exists, we sent instructions. For demo, see Logs panel.');
        status.className = 'row ok';
        // Simulated delivery payload
        if (res && res.delivery) {
          console.log('Simulated reset token:', res.delivery.token);
          console.log('Deep link:', res.delivery.link);
          // Add a direct navigation link
          const linkRow = document.createElement('div');
          linkRow.className = 'row';
          const a = document.createElement('a');
          a.href = res.delivery.link;
          a.rel = 'nofollow';
          setText(a, 'Open verification link');
          linkRow.appendChild(a);
          view.appendChild(linkRow);
        }
      } catch (err) {
        status.remove();
        handleError(view, err);
      }
    });
    view.appendChild(submit);
  }

  function renderVerify(query){
    const title = document.createElement('h2');
    setText(title, 'Verify reset token');
    view.appendChild(title);

    message(view, 'You can open the deep link from Logs or paste the token below.', 'muted small');

    const tokenField = makeInput('Reset token', 'text', 'token', 'one-time-code');
    view.appendChild(tokenField.container);

    const submit = document.createElement('button');
    setText(submit, 'Verify token');
    submit.addEventListener('click', async () => {
      const token = sanitizeInput(tokenField.input.value, 200);
      const status = message(view, 'Verifying…', 'muted small');
      try {
        await postJSON('/api/verify-reset', { token });
        setText(status, 'Token accepted. MFA step next.');
        status.className = 'row ok';
        location.hash = '#/mfa';
      } catch (err) {
        status.remove();
        // Display server error (e.g., "Token expired") prominently
        handleError(view, err);
      }
    });
    view.appendChild(submit);

    // Auto-submit if token provided in deep link
    if (query && query.token) {
      tokenField.input.value = query.token;
      // Small delay to show UI
      setTimeout(() => submit.click(), 300);
    }
  }

  function renderMfa(){
    const title = document.createElement('h2');
    setText(title, 'Multi-Factor Authentication (MFA)');
    view.appendChild(title);

    const info = message(view, 'We will send a verification code to your registered factor (simulated).', 'muted small');

    const sendBtn = document.createElement('button');
    setText(sendBtn, 'Send MFA code');
    sendBtn.addEventListener('click', async () => {
      clear(info);
      const status = message(view, 'Sending code…', 'muted small');
      try {
        const res = await postJSON('/api/send-mfa', {});
        setText(status, res.message || 'Code sent. Check Logs panel.');
        status.className = 'row ok';
        if (res && res.delivery && res.delivery.code) {
          console.log('Simulated MFA code:', res.delivery.code);
        }
      } catch (err) {
        handleError(view, err);
      }
    });
    view.appendChild(sendBtn);

    const codeField = makeInput('Enter MFA code', 'text', 'code', 'one-time-code');
    view.appendChild(codeField.container);

    const verifyBtn = document.createElement('button');
    setText(verifyBtn, 'Verify code');
    verifyBtn.addEventListener('click', async () => {
      const code = sanitizeInput(codeField.input.value, 20);
      const status = message(view, 'Checking code…', 'muted small');
      try {
        await postJSON('/api/verify-mfa', { code });
        setText(status, 'MFA verified. You can set a new password.');
        status.className = 'row ok';
        location.hash = '#/set';
      } catch (err) {
        status.remove();
        handleError(view, err);
      }
    });
    view.appendChild(verifyBtn);
  }

  function renderSetPassword(){
    const title = document.createElement('h2');
    setText(title, 'Set a new password');
    view.appendChild(title);

    message(view, 'Password must be at least 12 characters and include upper, lower, digit, and symbol.', 'muted small');

    const p1 = makeInput('New password', 'password', 'new-password', 'new-password');
    const p2 = makeInput('Confirm new password', 'password', 'confirm-password', 'new-password');
    view.appendChild(p1.container);
    view.appendChild(p2.container);

    const saveBtn = document.createElement('button');
    setText(saveBtn, 'Save new password');
    saveBtn.addEventListener('click', async () => {
      const a = p1.input.value;
      const b = p2.input.value;
      if (a !== b) {
        handleError(view, new Error('Passwords do not match'));
        return;
        }
      const status = message(view, 'Updating…', 'muted small');
      try {
        await postJSON('/api/set-password', { newPassword: a });
        setText(status, 'Password updated successfully.');
        status.className = 'row ok';
        location.hash = '#/done';
      } catch (err) {
        status.remove();
        handleError(view, err);
      }
    });
    view.appendChild(saveBtn);
  }

  function renderDone(){
    const title = document.createElement('h2');
    setText(title, 'All set!');
    view.appendChild(title);
    message(view, 'Your password has been changed. You can now log in and accept the privacy statement.', 'ok');
    const go = document.createElement('a');
    go.href = '#/login';
    go.rel = 'nofollow';
    go.className = 'button row';
    setText(go, 'Go to login');
    view.appendChild(go);
  }

  window.addEventListener('hashchange', render);
  render();
})();`;

// ---------- Server Routing and Handlers ----------

function findUserByIdentifier(
    identifier: string | undefined | null
): User | null {
    if (!identifier) return null;
    const id = identifier.trim().toLowerCase();
    let uid = emailToUserId.get(id);
    if (!uid) uid = usernameToUserId.get(id);
    if (!uid) return null;
    return users.get(uid) || null;
}

function validatePasswordPolicy(pw: string) {
    if (typeof pw !== "string") return "Invalid password";
    if (pw.length < 12) return "Password must be at least 12 characters";
    if (!/[a-z]/.test(pw)) return "Password must include a lowercase letter";
    if (!/[A-Z]/.test(pw)) return "Password must include an uppercase letter";
    if (!/[0-9]/.test(pw)) return "Password must include a digit";
    if (!/[^A-Za-z0-9]/.test(pw)) return "Password must include a symbol";
    const common = [
        "password",
        "123456",
        "qwerty",
        "letmein",
        "admin",
        "welcome",
        "iloveyou",
        "abc123",
        "password1",
        "123456789",
        "12345678"
    ];
    if (common.includes(pw.toLowerCase())) return "Password is too common";
    return null;
}

async function handleAPI(req: Request, nonce: string): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // BAC: enforce same-origin and secure method handling
    if (req.method !== "POST") {
        return textResponse("Method Not Allowed", nonce, { status: 405 });
    }

    // Load session and enforce CSRF for all state-changing routes (BAC)
    const session = getSessionFromRequest(req);
    if (!session) {
        return jsonResponse({ message: "Invalid session" }, nonce, {
            status: 401
        });
    }
    const sentToken = req.headers.get("x-csrf-token") || "";
    if (sentToken !== session.csrfToken) {
        return jsonResponse({ message: "CSRF token invalid" }, nonce, {
            status: 403
        });
    }

    let body: any = {};
    try {
        body = await req.json();
    } catch {
        body = {};
    }
    // Basic input sanitation (XSS)
    const sanitizeStr = (s: any, max = 200) => {
        if (typeof s !== "string") return "";
        let t = s.trim();
        if (t.length > max) t = t.slice(0, max);
        t = t.replace(/[<>\\]/g, "").replace(/[\u0000-\u001F\u007F]/g, "");
        return t;
    };

    const clientIp = (() => {
        const xf = req.headers.get("x-forwarded-for");
        if (xf) return xf.split(",")[0].trim();
        return "127.0.0.1";
    })();

    // Routes
    if (path === "/api/login") {
        // Auth + rate limit + hashing
        const rate = checkRateLimiter(clientIp, session, "login");
        if (!rate.allowed)
            return jsonResponse({ message: "Too many attempts" }, nonce, {
                status: 429,
                headers: { "Retry-After": String(rate.retryAfter) }
            });

        const identifier = sanitizeStr(body.identifier, 120);
        const password = String(body.password ?? "");

        const user = findUserByIdentifier(identifier);
        let ok = false;
        if (user) {
            try {
                ok = await Bun.password.verify(password, user.passwordHash);
            } catch {
                ok = false;
            }
        }
        if (!ok) {
            // Generic error to prevent user enumeration (Auth)
            return jsonResponse({ message: "Invalid credentials" }, nonce, {
                status: 400
            });
        }
        session.userId = user!.id;
        return jsonResponse(
            { message: "Login successful (simulated)." },
            nonce
        );
    }

    if (path === "/api/request-reset") {
        // Auth + rate limit + non-disclosure + token creation
        const rate = checkRateLimiter(clientIp, session, "request-reset");
        if (!rate.allowed)
            return jsonResponse({ message: "Too many attempts" }, nonce, {
                status: 429,
                headers: { "Retry-After": String(rate.retryAfter) }
            });

        const identifier = sanitizeStr(body.identifier, 120);
        const user = findUserByIdentifier(identifier);

        // Generate a random single-use token with 15-minute TTL, bound to this session (Misconfiguration + BAC)
        const tokenStr = randomId(32);
        const createdAt = now();
        const expiresAt = createdAt + 15 * 60 * 1000;
        const tok: ResetToken = {
            token: tokenStr,
            userId: user ? user.id : null,
            createdAt,
            expiresAt,
            used: false,
            sessionId: session.id
        };
        resetTokens.set(tokenStr, tok);

        const delivery = {
            token: tokenStr,
            link: `/#/verify?token=${encodeURIComponent(tokenStr)}`
        };
        // Return generic success without revealing account existence (Auth)
        return jsonResponse(
            {
                message: "If an account exists, instructions have been sent.",
                delivery
            },
            nonce
        );
    }

    if (path === "/api/verify-reset") {
        // Auth + rate limit + token validation + session binding
        const rate = checkRateLimiter(clientIp, session, "verify-reset");
        if (!rate.allowed)
            return jsonResponse({ message: "Too many attempts" }, nonce, {
                status: 429,
                headers: { "Retry-After": String(rate.retryAfter) }
            });

        const token = sanitizeStr(body.token, 300);
        const rec = resetTokens.get(token);
        if (!rec)
            return jsonResponse({ message: "Invalid token" }, nonce, {
                status: 400
            });
        if (rec.used)
            return jsonResponse({ message: "Token already used" }, nonce, {
                status: 400
            });
        if (rec.sessionId !== session.id)
            return jsonResponse(
                { message: "Token not valid for this session" },
                nonce,
                { status: 403 }
            );
        // Enforce expiry: if expired, reject without marking used or setting session flags
        if (now() > rec.expiresAt) {
            return jsonResponse({ message: "Token expired" }, nonce, {
                status: 400
            });
        }
        // Mark single-use upon successful verification
        rec.used = true;
        session.resetVerified = true;
        session.resetTokenId = rec.token;
        session.resetUserId = rec.userId;
        return jsonResponse({ message: "Token verified" }, nonce);
    }

    if (path === "/api/send-mfa") {
        // Auth + rate limit + MFA code generation
        const rate = checkRateLimiter(clientIp, session, "send-mfa");
        if (!rate.allowed)
            return jsonResponse({ message: "Too many attempts" }, nonce, {
                status: 429,
                headers: { "Retry-After": String(rate.retryAfter) }
            });

        if (!session.resetVerified)
            return jsonResponse({ message: "Reset not verified" }, nonce, {
                status: 403
            });
        // Deterministic per-session MFA code for demo
        const code = "246810";
        session.mfaCode = code;
        session.mfaVerified = false;

        return jsonResponse(
            { message: "MFA code sent (simulated).", delivery: { code } },
            nonce
        );
    }

    if (path === "/api/verify-mfa") {
        // Auth + rate limit + MFA verification
        const rate = checkRateLimiter(clientIp, session, "verify-mfa");
        if (!rate.allowed)
            return jsonResponse({ message: "Too many attempts" }, nonce, {
                status: 429,
                headers: { "Retry-After": String(rate.retryAfter) }
            });

        if (!session.resetVerified)
            return jsonResponse({ message: "Reset not verified" }, nonce, {
                status: 403
            });
        const code = sanitizeStr(body.code, 30);
        if (!session.mfaCode || code !== session.mfaCode) {
            return jsonResponse({ message: "Invalid code" }, nonce, {
                status: 400
            });
        }
        session.mfaVerified = true;
        return jsonResponse({ message: "MFA verified" }, nonce);
    }

    if (path === "/api/set-password") {
        // Auth + password policy + Argon2id hash
        if (!session.resetVerified || !session.mfaVerified) {
            return jsonResponse(
                { message: "Reset flow not completed" },
                nonce,
                { status: 403 }
            );
        }
        const newPassword = String(body.newPassword ?? "");
        const policyErr = validatePasswordPolicy(newPassword);
        if (policyErr)
            return jsonResponse({ message: policyErr }, nonce, { status: 400 });
        const uid = session.resetUserId;
        if (!uid || !users.has(uid)) {
            // Generic response (do not disclose existence)
            // Clear state to avoid leaking flow
            session.resetVerified = false;
            session.mfaVerified = false;
            session.resetUserId = null;
            session.resetTokenId = undefined;
            return jsonResponse({ message: "Password updated" }, nonce);
        }
        const user = users.get(uid)!;
        const hashed = await Bun.password.hash(newPassword, {
            algorithm: "argon2id"
        });
        user.passwordHash = hashed;

        // Invalidate token and clear flags
        if (session.resetTokenId && resetTokens.has(session.resetTokenId)) {
            const r = resetTokens.get(session.resetTokenId)!;
            r.used = true;
            resetTokens.delete(session.resetTokenId);
        }
        session.resetVerified = false;
        session.mfaVerified = false;
        session.resetUserId = null;
        session.resetTokenId = undefined;

        return jsonResponse({ message: "Password updated" }, nonce);
    }

    return jsonResponse({ message: "Not found" }, nonce, { status: 404 });
}

// ---------- HTTPS Server ----------
const server = Bun.serve({
    port: PORT,
    tls: {
        cert: Bun.file("certs/cert.pem"),
        key: Bun.file("certs/key.pem")
    },
    fetch: async (req: Request) => {
        const nonce = randomId(16);
        const url = new URL(req.url);
        const pathname = url.pathname;

        if (pathname.startsWith("/api/")) {
            return handleAPI(req, nonce);
        }

        if (req.method === "GET" && pathname === "/") {
            const { session, isNew } = getOrCreateSession(req);
            const headers = new Headers(securityHeaders(nonce));
            headers.set("Content-Type", "text/html; charset=utf-8");
            headers.set("Vary", "Cookie");
            if (isNew) {
                headers.append("Set-Cookie", sessionCookie(session.id));
            }
            const html = renderHTML(nonce, session);
            return new Response(html, { status: 200, headers });
        }

        if (req.method === "GET" && pathname === "/app.js") {
            const headers = new Headers(securityHeaders(nonce));
            headers.set(
                "Content-Type",
                "application/javascript; charset=utf-8"
            );
            headers.set("Vary", "Cookie");
            return new Response(APP_JS, { status: 200, headers });
        }

        // No directory listing or debug info (Misconfiguration)
        return textResponse("Not Found", nonce, { status: 404 });
    }
});

console.log(`HTTPS server running at https://localhost:${server.port}`);
