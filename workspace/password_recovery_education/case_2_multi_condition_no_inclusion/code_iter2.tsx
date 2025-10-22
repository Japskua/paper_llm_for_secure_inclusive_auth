
/**
 * app.ts - Single-file HTTPS Bun server + SPA
 * Password Recovery System Demo
 *
 * Run with: bun app.ts
 *
 * Notes:
 * - All mocks/logs are printed to browser console and mirrored to on-page Logs panel.
 * - No external network calls; all logic in this file.
 * - Comments map back to Security Requirements sections where relevant.
 */

/// <reference lib="dom" />

// ----------------------------- In-memory stores -----------------------------
// [Security 1: Broken Access Control] Sessions are isolated in-memory with CSRF per session.
// [Security 3: Misconfiguration] No persistence; no sensitive info is exposed.
type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  ip: string;
  pendingUser?: string;
  user?: string;
  pendingMFA?: boolean;
  mfaCode?: string;
  mfaExpiresAt?: number;
  mfaAttempts?: number;
  mfaNonce?: string;
  resetUser?: string;
  resetToken?: string;
  accessibility?: boolean;
  // Rate limit buckets per key (e.g., "login", "request-reset")
  rate: Record<string, number[]>;
};

type ResetToken = {
  token: string;
  expiresAt: number;
  used: boolean;
};

type User = {
  username: string;
  email: string;
  passwordHash: string;
  expired: boolean;
  resetTokens: ResetToken[];
};

// Deterministic single in-memory user store
const users = new Map<string, User>();

// Initialize demo user 'alex' with expired password.
const initialAlexPassword = "Al3xOldPass!!AA"; // strong old password
const alexHash = await Bun.password.hash(initialAlexPassword, {
  algorithm: "bcrypt",
  cost: 10,
});
users.set("alex", {
  username: "alex",
  email: "alex@example.edu",
  passwordHash: alexHash,
  expired: true,
  resetTokens: [],
});

// In-memory session store
const sessions = new Map<string, Session>();

// ------------------------------- Util functions -----------------------------
function b64url(bytes: Uint8Array): string {
  // Node/Bun Buffer available
  // @ts-ignore
  return Buffer.from(bytes).toString("base64url");
}
function randomId(byteLen = 16): string {
  const arr = new Uint8Array(byteLen);
  crypto.getRandomValues(arr);
  return b64url(arr);
}
function now(): number {
  return Date.now();
}

function getIP(req: Request): string {
  // No reverse proxy in this demo; use header if present; otherwise localhost
  const xf = req.headers.get("x-forwarded-for");
  if (xf) return xf.split(",")[0].trim();
  return "127.0.0.1";
}

function parseCookies(h: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  const parts = h.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join("=") || "");
  }
  return out;
}

function cookieSerialize(name: string, val: string, attrs: Record<string, string | number | boolean> = {}) {
  let s = `${name}=${encodeURIComponent(val)}`;
  if (attrs.Path) s += `; Path=${attrs.Path}`;
  if (attrs.HttpOnly) s += `; HttpOnly`;
  if (attrs.Secure) s += `; Secure`;
  if (attrs.SameSite) s += `; SameSite=${attrs.SameSite}`;
  if (attrs["Max-Age"]) s += `; Max-Age=${attrs["Max-Age"]}`;
  if (attrs.Expires) s += `; Expires=${attrs.Expires}`;
  return s;
}

// Simple per-session rate limiter (retained for any future per-session checks)
function checkRate(session: Session, ip: string, key: string, limit = 5, windowMs = 5 * 60 * 1000): boolean {
  const buckets = session.rate || (session.rate = {});
  const nowMs = now();
  const bkey = `${key}:${ip}`;
  const arr = buckets[bkey] || (buckets[bkey] = []);
  // prune old
  while (arr.length && nowMs - arr[0] > windowMs) arr.shift();
  if (arr.length >= limit) return false;
  arr.push(nowMs);
  return true;
}

// -------------------- Global rate limiter (per IP, per action) --------------
// [Security 4: Throttling/Brute force mitigation — Global per-IP limiter]
const globalRate = new Map<string, number[]>();
function checkRateGlobal(ip: string, action: string, limit = 5, windowMs = 5 * 60 * 1000): boolean {
  const key = `${ip}:${action}`;
  const nowMs = now();
  let arr = globalRate.get(key);
  if (!arr) {
    arr = [];
    globalRate.set(key, arr);
  }
  // prune old timestamps
  while (arr.length && nowMs - arr[0] > windowMs) arr.shift();
  if (arr.length >= limit) return false;
  arr.push(nowMs);
  return true;
}

// ---------------------------- Security Headers ------------------------------
// [Security 3: Misconfiguration hardening: HTTPS+HSTS+CSP+secure headers]
function buildCSPForHTML(nonce: string) {
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join("; ");
  return csp;
}
function buildCSPForAPI() {
  // No scripts in JSON responses; lock it down
  const csp = [
    "default-src 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  return csp;
}

function commonSecurityHeaders(extra: Record<string, string> = {}) {
  return {
    // HSTS - enforce HTTPS
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    // XFO
    "X-Frame-Options": "DENY",
    // Referrer policy
    "Referrer-Policy": "no-referrer",
    // MIME sniffing
    "X-Content-Type-Options": "nosniff",
    // Minimal Permissions-Policy
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    ...extra,
  };
}

function jsonResponse(obj: any, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...commonSecurityHeaders({
        "Content-Security-Policy": buildCSPForAPI(),
      }),
    },
  });
}

// ---------------------------- CSRF and Sessions -----------------------------
// [Security 1: CSRF prevention — unique per session and validated on all POST /api/*]
function getOrCreateSession(req: Request): { session: Session; newCookie?: string } {
  const cookies = parseCookies(req.headers.get("cookie"));
  let sid = cookies["sid"];
  let sess: Session | undefined;
  if (sid) {
    sess = sessions.get(sid);
  }
  if (!sess) {
    sid = randomId(18);
    sess = {
      id: sid,
      csrf: randomId(18),
      createdAt: now(),
      ip: getIP(req),
      rate: {},
      accessibility: false,
    };
    sessions.set(sid, sess);
    const cookie = cookieSerialize("sid", sid, {
      Path: "/",
      HttpOnly: true,
      Secure: true,
      SameSite: "Strict",
      // Session cookie; no Max-Age for simplicity
    });
    return { session: sess, newCookie: cookie };
  }
  return { session: sess };
}

async function readJsonSafe<T>(req: Request): Promise<T | null> {
  try {
    const txt = await req.text();
    if (!txt) return {} as any;
    return JSON.parse(txt);
  } catch {
    return null;
  }
}

function validateCSRF(req: Request, session: Session): boolean {
  const token = req.headers.get("x-csrf-token") || "";
  return token === session.csrf;
}

// ----------------------------- HTML Rendering -------------------------------
function renderHTML(nonce: string, session: Session): string {
  // Inline HTML SPA. Avoid reflecting unsanitized user input.
  // [Security 2: XSS prevention — single trusted script with nonce, no inline event handlers]
  const accessibilityEnabled = !!session.accessibility;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>University Portal — Secure Password Recovery Demo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="${buildCSPForHTML(nonce).replace(/"/g, "&quot;")}">
  <style>
    /* Base styles with dyslexia-friendly optional mode */
    :root {
      --bg: #0b0c10;
      --fg: #eaf2f8;
      --accent: #4fc3f7;
      --muted: #a0b0c0;
      --danger: #ff6b6b;
      --ok: #7ed957;
    }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Arial, sans-serif;
      background: var(--bg);
      color: var(--fg);
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
    }
    header, footer {
      padding: 12px 16px;
      background: #0e1116;
      border-bottom: 1px solid #1b2838;
    }
    header h1 {
      margin: 0;
      font-size: 1.1rem;
      letter-spacing: 0.3px;
    }
    .container {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
      padding: 16px;
      max-width: 860px;
      margin: 0 auto;
      width: 100%;
    }
    nav a {
      color: var(--accent);
      text-decoration: none;
      margin-right: 12px;
    }
    nav a:focus, nav a:hover {
      text-decoration: underline;
    }
    .card {
      background: #11161f;
      border: 1px solid #1b2838;
      border-radius: 10px;
      padding: 16px;
      box-shadow: 0 0 0 3px rgba(79,195,247,0.02) inset;
    }
    label {
      display: block;
      margin: 10px 0 6px;
      color: var(--muted);
      font-weight: 600;
    }
    input[type="text"], input[type="password"], input[type="email"] {
      width: 100%;
      padding: 12px 10px;
      border: 1px solid #27384f;
      border-radius: 8px;
      background: #0b1018;
      color: var(--fg);
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(79,195,247,0.15);
    }
    button {
      background: var(--accent);
      color: #002b36;
      border: none;
      border-radius: 8px;
      padding: 10px 14px;
      font-weight: 700;
      cursor: pointer;
      margin-top: 12px;
    }
    button.secondary {
      background: #25364d;
      color: var(--fg);
    }
    .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .muted { color: var(--muted); }
    .error { color: var(--danger); }
    .ok { color: var(--ok); }
    .hidden { display: none !important; }

    /* Dyslexia-friendly mode */
    body.accessible {
      font-size: 18px;
      line-height: 1.8;
      letter-spacing: 0.3px;
      word-spacing: 2px;
    }
    body.accessible input, body.accessible button {
      font-size: 1.1rem;
      padding: 14px 16px;
    }
    body.accessible .card {
      border-width: 2px;
    }

    #logs {
      background: #0a0f16;
      border: 1px dashed #2a3a4d;
      padding: 10px;
      border-radius: 8px;
      max-height: 160px;
      overflow: auto;
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px;
      white-space: pre-wrap;
    }
    .kbd {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      background: #101820;
      border: 1px solid #2a3a4d;
      border-radius: 4px;
      padding: 2px 6px;
    }
  </style>
</head>
<body>
  <header>
    <div class="row" style="justify-content: space-between;">
      <h1>University Portal — Account Access</h1>
      <div class="row">
        <nav>
          <a href="#login">Login</a>
          <a href="#forgot">Forgot Password</a>
          <a href="#help">Help</a>
        </nav>
        <button id="toggleAccBtn" class="secondary" aria-pressed="${accessibilityEnabled ? "true" : "false"}" aria-label="Toggle dyslexia-friendly mode">Accessibility</button>
      </div>
    </div>
  </header>

  <main class="container">
    <section id="view" class="card" aria-live="polite">
      Loading…
    </section>
    <section class="card">
      <h3>Logs (mock delivery)</h3>
      <div id="logs" aria-live="polite"></div>
      <p class="muted">For demo purposes only: MFA codes and reset tokens are delivered via console.log and mirrored here.</p>
    </section>
  </main>

  <footer class="muted">
    <div class="container">
      <small>Security Demo: HTTPS, MFA, CSRF, CSP, rate limiting, bcrypt hashing. No external calls. Tokens are mocked.</small>
    </div>
  </footer>

  <script nonce="${nonce}">
    // Client SPA script
    // [Security 2: XSS] No untrusted scripts; this script is authorized via CSP nonce.
    // [Security 5: SSRF/Open redirect] Only hash-based internal navigation is used.

    // Server-provided session data
    window.__CSRF = ${JSON.stringify(session.csrf)};
    window.__PREFS = ${JSON.stringify({ accessibility: !!session.accessibility })};
    window.__MFANONCE = null;

    (function(){
      const view = document.getElementById('view');
      const logsEl = document.getElementById('logs');
      const accBtn = document.getElementById('toggleAccBtn');

      function setAccessible(on) {
        document.body.classList.toggle('accessible', !!on);
        accBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
      }
      setAccessible(window.__PREFS.accessibility);

      // Mirror logs to console and panel
      function log(msg) {
        try {
          console.log("[Mock Delivery]", msg);
        } catch {}
        const line = document.createElement('div');
        line.textContent = String(msg);
        logsEl.appendChild(line);
        logsEl.scrollTop = logsEl.scrollHeight;
      }

      // Simple helpers
      function sanitize(s) {
        // We avoid HTML injection by using textContent everywhere; sanitize returns string.
        return String(s || '');
      }
      function setMessage(el, msg, cls) {
        el.textContent = sanitize(msg);
        el.className = cls || '';
      }

      async function api(path, body) {
        const res = await fetch(path, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.__CSRF
          },
          body: JSON.stringify(body || {})
        });
        const data = await res.json().catch(()=>({}));
        return { ok: res.ok, status: res.status, data };
      }

      // Views
      function renderLogin() {
        const c = document.createElement('div');
        c.innerHTML = '';
        const h = document.createElement('h2');
        h.textContent = 'Login';
        const p = document.createElement('p');
        p.className = 'muted';
        p.textContent = 'Sign in to your account. If your password is expired, you will be prompted to create a new one.';

        const form = document.createElement('form');
        form.autocomplete = 'off';
        form.innerHTML = '';
        const uLabel = document.createElement('label'); uLabel.textContent = 'Username';
        const u = document.createElement('input'); u.type='text'; u.name='username'; u.required = true; u.autocomplete='username';
        const pLabel = document.createElement('label'); pLabel.textContent = 'Password';
        const pw = document.createElement('input'); pw.type='password'; pw.name='password'; pw.required = true; pw.autocomplete='current-password';
        const msg = document.createElement('div'); msg.className='muted'; msg.id='loginMsg';
        const btn = document.createElement('button'); btn.textContent = 'Sign In';

        form.appendChild(uLabel); form.appendChild(u);
        form.appendChild(pLabel); form.appendChild(pw);
        form.appendChild(btn);
        c.appendChild(h); c.appendChild(p); c.appendChild(form); c.appendChild(msg);

        form.addEventListener('submit', async (e)=>{
          e.preventDefault();
          setMessage(msg, 'Checking…', 'muted');
          const {ok, status, data} = await api('/api/login', { username: u.value, password: pw.value });
          if (!ok) {
            if (status === 429) setMessage(msg, 'Too many attempts. Please wait before trying again.', 'error');
            else setMessage(msg, 'Invalid credentials.', 'error');
            return;
          }
          // MFA required
          if (data && data.log) log(data.log);
          if (data && data.mfaNonce) {
            window.__MFANONCE = data.mfaNonce;
          } else {
            window.__MFANONCE = null;
          }
          location.hash = '#mfa';
        });

        mount(c);
      }

      function renderMFA() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Multi‑Factor Authentication';
        const p = document.createElement('p'); p.className='muted';
        p.textContent = 'Enter the 6‑digit code. For demo, the code is sent via console/logs.';
        const form = document.createElement('form');
        const l = document.createElement('label'); l.textContent = 'MFA Code';
        const code = document.createElement('input'); code.type='text'; code.inputMode='numeric'; code.maxLength=6; code.required=true; code.autocomplete='one-time-code';
        const btn = document.createElement('button'); btn.textContent = 'Verify';
        const msg = document.createElement('div'); msg.className='muted';

        form.appendChild(l); form.appendChild(code); form.appendChild(btn);
        c.appendChild(h); c.appendChild(p); c.appendChild(form); c.appendChild(msg);
        form.addEventListener('submit', async (e)=>{
          e.preventDefault();
          setMessage(msg, 'Verifying…', 'muted');
          const body = { code: code.value, mfaNonce: window.__MFANONCE };
          const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.__CSRF },
            body: JSON.stringify(body)
          });
          const data = await res.json().catch(()=>({}));
          if (!res.ok) {
            if (res.status === 401 && data && data.message === 'MFA expired; sign in again') {
              setMessage(msg, 'MFA session expired. Please sign in again.', 'error');
              log('MFA expired; please sign in again.');
              setTimeout(()=>{ location.hash = '#login'; }, 800);
              return;
            }
            if (res.status === 429) {
              if (data && data.message === 'Too many MFA attempts; sign in again') {
                setMessage(msg, 'Too many incorrect codes. Please sign in again.', 'error');
                log('Too many MFA attempts; please sign in again.');
                setTimeout(()=>{ location.hash = '#login'; }, 800);
              } else {
                setMessage(msg, 'Too many attempts. Please wait before trying again.', 'error');
                log('Global rate limit reached for MFA verification.');
              }
              return;
            }
            setMessage(msg, 'Invalid or expired code.', 'error');
            return;
          }
          if (data && data.log) log(data.log);
          if (data && data.requirePasswordChange) {
            location.hash = '#new-password';
          } else {
            location.hash = '#success';
          }
        });

        mount(c);
      }

      function renderForgot() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Forgot Password';
        const p = document.createElement('p'); p.className='muted';
        p.textContent = 'Enter your university email or username. If an account exists, a reset link will be delivered.';
        const form = document.createElement('form');
        const l = document.createElement('label'); l.textContent='Email or Username';
        const id = document.createElement('input'); id.type='text'; id.required=true; id.autocomplete='username email';
        const btn = document.createElement('button'); btn.textContent='Request Reset';
        const msg = document.createElement('div'); msg.className='muted';
        const manual = document.createElement('p'); manual.className='muted';
        const link = document.createElement('a'); link.href='#reset'; link.textContent='Have a reset code already? Enter it here.';
        manual.appendChild(link);

        form.appendChild(l); form.appendChild(id); form.appendChild(btn);
        c.appendChild(h); c.appendChild(p); c.appendChild(form); c.appendChild(msg); c.appendChild(manual);

        form.addEventListener('submit', async (e)=>{
          e.preventDefault();
          setMessage(msg, 'Processing…', 'muted');
          const {ok, status, data} = await api('/api/request-reset', { identifier: id.value });
          if (status === 429) { setMessage(msg, 'Too many requests. Try again later.', 'error'); return; }
          setMessage(msg, 'If an account exists, a password reset link has been sent.', ok ? 'ok' : 'muted');
          if (data && data.tokenHint) {
            // Build link using current origin
            const linkUrl = location.origin + '/#reset?token=' + encodeURIComponent(data.tokenHint);
            log('Reset token (demo): ' + data.tokenHint + ' — Link: ' + linkUrl);
          } else if (data && data.log) {
            log(data.log);
          }
        });

        mount(c);
      }

      function renderEnterReset() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Enter Reset Code';
        const p = document.createElement('p'); p.className='muted';
        p.textContent = 'Paste the reset token you received.';
        const form = document.createElement('form');
        const l = document.createElement('label'); l.textContent='Reset token';
        const tok = document.createElement('input'); tok.type='text'; tok.required=true; tok.autocomplete='one-time-code';
        const btn = document.createElement('button'); btn.textContent='Validate';
        const msg = document.createElement('div'); msg.className='muted';

        form.appendChild(l); form.appendChild(tok); form.appendChild(btn);
        c.appendChild(h); c.appendChild(p); c.appendChild(form); c.appendChild(msg);

        form.addEventListener('submit', async (e)=>{
          e.preventDefault();
          setMessage(msg, 'Validating…', 'muted');
          const {ok, data} = await api('/api/validate-reset', { token: tok.value });
          if (!ok) { setMessage(msg, 'Invalid or expired token.', 'error'); return; }
          if (data && data.log) log(data.log);
          location.hash = '#new-password';
        });

        mount(c);
      }

      function passwordStrength(pw) {
        const a = pw.length >= 12;
        const b = /[a-z]/.test(pw);
        const c = /[A-Z]/.test(pw);
        const d = /[0-9]/.test(pw);
        const e = /[^A-Za-z0-9]/.test(pw);
        return a && b && c && d && e;
      }

      function renderNewPassword() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Create New Password';
        const p = document.createElement('p'); p.className='muted';
        p.textContent = 'Choose a strong password: at least 12 characters with upper, lower, digit, and special character.';
        const form = document.createElement('form');
        const l1 = document.createElement('label'); l1.textContent='New password';
        const pw1 = document.createElement('input'); pw1.type='password'; pw1.required=true; pw1.autocomplete='new-password';
        const l2 = document.createElement('label'); l2.textContent='Confirm password';
        const pw2 = document.createElement('input'); pw2.type='password'; pw2.required=true; pw2.autocomplete='new-password';
        const btn = document.createElement('button'); btn.textContent='Save Password';
        const msg = document.createElement('div'); msg.className='muted';

        form.appendChild(l1); form.appendChild(pw1);
        form.appendChild(l2); form.appendChild(pw2);
        form.appendChild(btn);
        c.appendChild(h); c.appendChild(p); c.appendChild(form); c.appendChild(msg);

        form.addEventListener('submit', async (e)=>{
          e.preventDefault();
          if (pw1.value !== pw2.value) { setMessage(msg, 'Passwords do not match.', 'error'); return; }
          if (!passwordStrength(pw1.value)) { setMessage(msg, 'Password does not meet the strength policy.', 'error'); return; }
          setMessage(msg, 'Saving…', 'muted');
          const {ok, data} = await api('/api/set-password', { password: pw1.value });
          if (!ok) { setMessage(msg, (data && data.message) || 'Unable to set password.', 'error'); return; }
          if (data && data.log) log(data.log);
          location.hash = '#success';
        });

        mount(c);
      }

      function renderSuccess() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Success';
        const p = document.createElement('p'); p.className='ok';
        p.textContent = 'Password updated. You can now access the university portal.';
        const a = document.createElement('a'); a.href='#login'; a.textContent='Return to Login';
        c.appendChild(h); c.appendChild(p); c.appendChild(a);
        mount(c);
      }

      function renderHelp() {
        const c = document.createElement('div');
        const h = document.createElement('h2'); h.textContent = 'Help & Safety';
        const ul = document.createElement('ul');
        const points = [
          'Do not share passwords or reset links via email or chat.',
          'Always check the address bar for https:// and the correct domain.',
          'MFA codes will never be requested by staff. Only enter them here.',
          'For this demo, MFA and reset tokens are logged via console and shown in the Logs panel.',
          'We never reveal whether a username or email exists.',
          'If you suspect phishing, navigate directly to the portal rather than using links in messages.'
        ];
        for (const t of points) {
          const li = document.createElement('li'); li.textContent = t; ul.appendChild(li);
        }
        c.appendChild(h); c.appendChild(ul);
        mount(c);
      }

      // Mount helper ensures text-only insertion to avoid XSS
      function mount(el) {
        while (view.firstChild) view.removeChild(view.firstChild);
        view.appendChild(el);
      }

      // Router
      async function route() {
        const h = location.hash || '#login';
        // Support reset via link: #reset?token=...
        if (h.startsWith('#reset?')) {
          const qs = new URLSearchParams(h.slice('#reset?'.length));
          const token = qs.get('token');
          if (token) {
            log('Validating token from link…');
            const {ok, data} = await api('/api/validate-reset', { token });
            if (ok) {
              if (data && data.log) log(data.log);
              location.hash = '#new-password';
              return;
            } else {
              log('Invalid or expired token.');
              renderEnterReset();
              return;
            }
          }
        }
        switch (h) {
          case '#login': renderLogin(); break;
          case '#forgot': renderForgot(); break;
          case '#reset': renderEnterReset(); break;
          case '#new-password': renderNewPassword(); break;
          case '#mfa': renderMFA(); break;
          case '#success': renderSuccess(); break;
          case '#help': renderHelp(); break;
          default: renderLogin(); break;
        }
      }

      window.addEventListener('hashchange', route);
      route();

      // Accessibility toggle
      accBtn.addEventListener('click', async ()=>{
        const enabled = !document.body.classList.contains('accessible');
        setAccessible(enabled);
        // Persist per-session
        const {ok} = await api('/api/accessibility', { enabled });
        if (!ok) {
          // revert UI if failed (unlikely)
          setAccessible(!enabled);
        }
      });

      // On initial load, inform about mock behavior
      log('This is a demo. MFA codes and reset tokens will appear here.');
    })();
  </script>
</body>
</html>`;
}

// ------------------------------ API Handlers --------------------------------
async function handleAPI(req: Request, session: Session): Promise<Response> {
  // Enforce CSRF on all sensitive POST routes
  if (req.method !== "POST") {
    return jsonResponse({ ok: false, message: "Method Not Allowed" }, 405);
  }
  if (!validateCSRF(req, session)) {
    // [Security 1: CSRF] CSRF token missing/invalid => 403
    return jsonResponse({ ok: false, message: "CSRF validation failed" }, 403);
  }

  const url = new URL(req.url);
  const path = url.pathname;

  // Reject any absolute redirect/next parameters to avoid open redirect/SSRF
  // [Security 5: SSRF/Open redirect prevention]
  const nextParam = url.searchParams.get("next") || "";
  if (nextParam && (/^https?:\/\//i).test(nextParam)) {
    return jsonResponse({ ok: false, message: "Invalid next parameter" }, 400);
  }

  if (path === "/api/login") {
    const ip = getIP(req);
    if (!checkRateGlobal(ip, "login", 5, 5 * 60 * 1000)) {
      return jsonResponse({ ok: false, message: "Too many attempts" }, 429);
    }
    const body = await readJsonSafe<{ username?: string; password?: string }>(req);
    if (!body) return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    const username = (body.username || "").toLowerCase().trim();
    const password = body.password || "";

    // Generic error to avoid user enumeration
    const genericErr = () => jsonResponse({ ok: false, message: "Invalid credentials" }, 401);

    const user = users.get(username);
    if (!user) return genericErr();
    const ok = await Bun.password.verify(password, user.passwordHash);
    if (!ok) return genericErr();

    // Generate per-session MFA code
    // [Security 4: MFA implemented]
    const code = (Math.floor(100000 + Math.random() * 900000)).toString();
    session.pendingUser = user.username;
    session.pendingMFA = true;
    session.mfaCode = code;
    session.mfaExpiresAt = now() + 5 * 60 * 1000;
    session.mfaAttempts = 5;
    session.mfaNonce = randomId(16);

    // For demo: send code to client for console/logging. Do not reveal user in UI response.
    return jsonResponse({
      ok: true,
      mfaRequired: true,
      mfaNonce: session.mfaNonce,
      // The client mirrors this to console and Logs panel
      log: `MFA code (demo): ${code}`
    });
  }

  if (path === "/api/verify-mfa") {
    const ip = getIP(req);
    if (!checkRateGlobal(ip, "verify-mfa", 5, 5 * 60 * 1000)) {
      return jsonResponse({ ok: false, message: "Too many attempts" }, 429);
    }
    const body = await readJsonSafe<{ code?: string; mfaNonce?: string }>(req);
    if (!body) return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    const code = (body.code || "").trim();
    const providedNonce = (body.mfaNonce || "").trim();
    if (!session.pendingMFA || !session.pendingUser || !session.mfaCode) {
      return jsonResponse({ ok: false, message: "No pending MFA" }, 400);
    }

    // Expiry check prior to comparison
    if (typeof session.mfaExpiresAt === "number" && now() > session.mfaExpiresAt) {
      // Clear MFA state (terminal expiry)
      session.pendingMFA = false;
      session.mfaCode = undefined;
      session.mfaExpiresAt = undefined;
      session.mfaAttempts = undefined;
      session.mfaNonce = undefined;
      return jsonResponse({ ok: false, message: "MFA expired; sign in again" }, 401);
    }

    // Nonce must match
    if (!session.mfaNonce || providedNonce !== session.mfaNonce) {
      return jsonResponse({ ok: false, message: "Unauthorized" }, 401);
    }

    // Validate the code
    if (code !== session.mfaCode) {
      if (typeof session.mfaAttempts === "number") {
        session.mfaAttempts = Math.max(0, session.mfaAttempts - 1);
        if (session.mfaAttempts <= 0) {
          // Terminal lockout: clear MFA state
          session.pendingMFA = false;
          session.mfaCode = undefined;
          session.mfaExpiresAt = undefined;
          session.mfaAttempts = undefined;
          session.mfaNonce = undefined;
          return jsonResponse({ ok: false, message: "Too many MFA attempts; sign in again" }, 429);
        }
      }
      return jsonResponse({ ok: false, message: "Invalid code" }, 401);
    }

    // Success
    session.user = session.pendingUser;
    session.pendingMFA = false;
    session.pendingUser = undefined;
    session.mfaCode = undefined;
    session.mfaExpiresAt = undefined;
    session.mfaAttempts = undefined;
    session.mfaNonce = undefined;

    const u = users.get(session.user!);
    const requireChange = !!u?.expired;

    // If password is expired, authorize a one-time password set via session-bound reset state
    if (requireChange && u) {
      session.resetUser = u.username;
      session.resetToken = randomId(16); // session-local marker; not exposed elsewhere
    }

    return jsonResponse({
      ok: true,
      requirePasswordChange: requireChange,
      log: requireChange ? "Login OK. Password is expired; please set a new one." : "Login OK."
    });
  }

  if (path === "/api/request-reset") {
    const ip = getIP(req);
    if (!checkRateGlobal(ip, "request-reset", 5, 5 * 60 * 1000)) {
      return jsonResponse({ ok: false, message: "Too many requests" }, 429);
    }
    const body = await readJsonSafe<{ identifier?: string }>(req);
    if (!body) return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    const ident = (body.identifier || "").toLowerCase().trim();

    // Generic response regardless of existence
    let tokenHint: string | undefined;
    // Only create a token if user exists (username or email)
    let user: User | undefined;
    if (ident.includes("@")) {
      user = Array.from(users.values()).find(u => u.email.toLowerCase() === ident);
    } else {
      user = users.get(ident);
    }
    if (user) {
      // [Security 3: Random, single-use, short-lived reset tokens]
      const token = randomId(24);
      const expiresAt = now() + 10 * 60 * 1000;
      user.resetTokens.push({ token, expiresAt, used: false });
      tokenHint = token;
    }
    return jsonResponse({
      ok: true,
      // do not reveal whether user exists
      message: "If an account exists, a password reset link has been sent.",
      // token returned only for demo logging in browser
      tokenHint: tokenHint || null
    });
  }

  if (path === "/api/validate-reset") {
    const body = await readJsonSafe<{ token?: string }>(req);
    if (!body) return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    const token = (body.token || "").trim();
    // Validate token across all users
    let matchedUser: User | undefined;
    let matched: ResetToken | undefined;
    for (const u of users.values()) {
      const t = u.resetTokens.find(rt => rt.token === token && !rt.used && rt.expiresAt > now());
      if (t) { matchedUser = u; matched = t; break; }
    }
    if (!matchedUser || !matched) {
      return jsonResponse({ ok: false, message: "Invalid or expired token" }, 400);
    }
    // Mark single-use token as used immediately
    matched.used = true;
    // Bind the reset token to the session
    session.resetUser = matchedUser.username;
    session.resetToken = matched.token;
    return jsonResponse({ ok: true, log: "Reset token validated. You can now set a new password." });
  }

  if (path === "/api/set-password") {
    const body = await readJsonSafe<{ password?: string }>(req);
    if (!body) return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    const pw = body.password || "";

    // [Security 4: Strong password policy]
    const strong = pw.length >= 12 && /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
    if (!strong) return jsonResponse({ ok: false, message: "Password does not meet policy" }, 400);

    // [Security 1: Prevent IDOR]
    // Authorize ONLY via session-bound reset state (ignore tokens in body)
    if (!session.resetUser || !session.resetToken) {
      return jsonResponse({ ok: false, message: "Unauthorized" }, 401);
    }
    const targetUser = users.get(session.resetUser);
    if (!targetUser) {
      return jsonResponse({ ok: false, message: "Unauthorized" }, 401);
    }

    const newHash = await Bun.password.hash(pw, { algorithm: "bcrypt", cost: 10 });
    targetUser.passwordHash = newHash;
    targetUser.expired = false;
    // Invalidate all reset tokens for this user
    targetUser.resetTokens.forEach(rt => rt.used = true);
    // One-time success; clear session reset authorization
    session.resetUser = undefined;
    session.resetToken = undefined;

    return jsonResponse({ ok: true, log: "Password updated (demo). All reset tokens invalidated." });
  }

  if (path === "/api/accessibility") {
    const body = await readJsonSafe<{ enabled?: boolean }>(req);
    if (!body || typeof body.enabled !== "boolean") return jsonResponse({ ok: false, message: "Bad Request" }, 400);
    session.accessibility = body.enabled;
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ ok: false, message: "Not Found" }, 404);
}

// ------------------------------ HTTP Handlers -------------------------------
async function handleGET(req: Request): Promise<Response> {
  const { session, newCookie } = getOrCreateSession(req);
  const nonce = randomId(18);
  const html = renderHTML(nonce, session);
  const headers: Record<string, string> = {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": buildCSPForHTML(nonce),
    ...commonSecurityHeaders(),
  };
  if (newCookie) headers["Set-Cookie"] = newCookie;
  return new Response(html, {
    status: 200,
    headers,
  });
}

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);

  // Only support our single-page app and same-file API
  if (req.method === "GET" && url.pathname === "/") {
    return handleGET(req);
  }

  if (url.pathname.startsWith("/api/")) {
    // Must create session if missing (should exist from GET /)
    const { session, newCookie } = getOrCreateSession(req);
    const resp = await handleAPI(req, session);
    if (newCookie) {
      // Bubble cookie header into response if session was newly created via API (unlikely)
      const headers = new Headers(resp.headers);
      headers.set("Set-Cookie", newCookie);
      return new Response(resp.body, { status: resp.status, headers });
    }
    return resp;
  }

  // SPA: route all other GET to /
  if (req.method === "GET") {
    return handleGET(req);
  }

  return new Response("Not Found", { status: 404, headers: commonSecurityHeaders() });
}

// ------------------------------- HTTPS Server -------------------------------
// [Security 3: Enforce HTTPS; use provided mkcert certs]
const port = Number(process.env.PORT || 8443);

const server = Bun.serve({
  port,
  tls: {
    // Ready-made TLS certs will be placed at these paths by the evaluator
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handleRequest,
  error(err) {
    // [Security 3: No stack traces in production responses]
    console.error("Server error:", err?.message || err);
    return new Response("Internal Error", { status: 500, headers: commonSecurityHeaders() });
  },
});

// Log startup (server-side)
console.log(`HTTPS server running on https://localhost:${server.port} (SPA served from /)`);

// ------------------------------ End of file ---------------------------------
