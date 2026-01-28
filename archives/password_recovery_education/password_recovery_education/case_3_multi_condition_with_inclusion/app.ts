
/**
 * app.ts
 * Single-file HTTPS Bun server + SPA implementing a secure, inclusive Password Recovery System.
 * Run with: bun app.ts
 *
 * Major sections include comments that map to Security and Inclusivity requirements.
 */

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

// ---------------------------- In-memory state (no persistence) ----------------------------
// [Security: Identification & Authentication] Users store with bcrypt hashing via Bun.password
type User = {
  id: string;
  email: string;
  username: string;
  passwordHash: string;
  mfaEnabled: boolean;
};

const users = new Map<string, User>();
const userByEmail = new Map<string, string>();
const userByUsername = new Map<string, string>();

const createUser = async (id: string, email: string, username: string, plainPassword: string, mfaEnabled: boolean) => {
  const passwordHash = await Bun.password.hash(plainPassword, { algorithm: "bcrypt", cost: 10 });
  const user: User = { id, email: email.toLowerCase(), username: username.toLowerCase(), passwordHash, mfaEnabled };
  users.set(id, user);
  userByEmail.set(user.email, id);
  userByUsername.set(user.username, id);
};

// Alex - initial account (fulfills "include Alex")
await createUser("u1", "alex@student.example.edu", "alex", "Start123!A", true);

// ---------------------------- Helpers ----------------------------
function randomId(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function makeNonce(): string {
  return randomId(16);
}

function now(): number {
  return Date.now();
}

function escapeHtml(str: string): string {
  return str
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// [Security: Injection] Simple input sanitizers - used to normalize inputs; we don't reflect them.
function sanitizeIdentifier(s: string): string {
  return s.toLowerCase().trim().replace(/[^a-z0-9@._+\-]/g, "").slice(0, 100);
}
function sanitizeEmail(s: string): string {
  return s.toLowerCase().trim().replace(/[^a-z0-9@._+\-]/g, "").slice(0, 200);
}
function sanitizeCode(s: string): string {
  return s.trim().replace(/[^A-Za-z0-9\-_.]/g, "").slice(0, 200);
}
function parseJSON<T = any>(body: string): T | null {
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}
function getCookieMap(req: Request): Record<string, string> {
  const cookie = req.headers.get("cookie") || "";
  const map: Record<string, string> = {};
  cookie.split(";").forEach((p) => {
    const [k, v] = p.split("=").map((s) => s?.trim());
    if (k && v) map[k] = v;
  });
  return map;
}

// [Security: CSRF] Sessions with CSRF token
type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  userId?: string;
  authenticated?: boolean;
  // Password reset context
  resetAllowed?: boolean;
  resetUserId?: string | null;
};

const sessions = new Map<string, Session>();

function getOrCreateSession(sid?: string): Session {
  if (sid && sessions.has(sid)) return sessions.get(sid)!;
  const newId = randomId(24);
  const csrf = randomId(24);
  const s: Session = { id: newId, csrf, createdAt: now() };
  sessions.set(newId, s);
  return s;
}

// [Security: MFA] Deterministic 6-digit code per session (expires) + store
type MfaEntry = {
  code: string;
  expiresAt: number;
  userId: string;
};
const mfaCodes = new Map<string, MfaEntry>(); // key: sessionId

function generateDeterministicCode(sessionId: string): string {
  let sum = 0;
  for (let i = 0; i < sessionId.length; i++) sum = (sum + sessionId.charCodeAt(i)) % 1000000;
  return sum.toString().padStart(6, "0");
}

// [Security: Reset tokens] Single-use, short-lived
type ResetToken = {
  token: string;
  userId: string | null; // null to avoid user existence leak (sink)
  createdAt: number;
  expiresAt: number;
  used: boolean;
};
const resetTokens = new Map<string, ResetToken>();

// [Security: Throttling] Simple fixed-window-ish limiter
const rateStore = new Map<string, number[]>();
const RATE_MAX = 5;
const RATE_WINDOW_MS = 60_000;

function rateLimited(key: string): boolean {
  const nowTs = now();
  const arr = rateStore.get(key) || [];
  const filtered = arr.filter((t) => nowTs - t < RATE_WINDOW_MS);
  filtered.push(nowTs);
  rateStore.set(key, filtered);
  return filtered.length > RATE_MAX;
}

// [Security: Password policy]
function passwordPolicyIssues(pw: string): string[] {
  const issues: string[] = [];
  if (pw.length < 10) issues.push("At least 10 characters");
  if (!/[a-z]/.test(pw)) issues.push("One lowercase letter");
  if (!/[A-Z]/.test(pw)) issues.push("One uppercase letter");
  if (!/[0-9]/.test(pw)) issues.push("One number");
  if (!/[^\w\s]/.test(pw)) issues.push("One symbol (e.g., !@#$)");
  return issues;
}

// ---------------------------- Security headers ----------------------------
// [Security: Security Misconfiguration] HSTS, CSP, Referrer-Policy, X-Content-Type-Options, frame protections
function makeSecurityHeaders(nonce: string): Headers {
  const h = new Headers();
  // [Security: 2 - Injection (XSS)] CSP with script-src 'self' and no inline scripts; styles are nonced.
  const csp = [
    "default-src 'none'",
    "script-src 'self'",
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "worker-src 'none'",
  ].join("; ");

  h.set("Content-Security-Policy", csp);
  h.set("Referrer-Policy", "no-referrer");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  // X-Frame-Options is largely superseded by CSP frame-ancestors but include for defense in depth
  h.set("X-Frame-Options", "DENY");
  // Disallow sniffing and caching of HTML/JSON
  h.set("Cache-Control", "no-store");
  return h;
}

// Cookie builder for session id
function sessionCookie(sid: string): string {
  // [Security: 1 - CSRF] Secure, HttpOnly, SameSite=Strict
  return `sid=${sid}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

// ---------------------------- HTML (SPA) ----------------------------
function htmlPage(nonce: string, csrf: string): string {
  // Minimal inline CSS (nonced). All client JS is served from /app.js with script-src 'self'.
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>University Portal — Password & Login Help</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${escapeHtml(csrf)}">
  <style nonce="${nonce}">
    /* Inclusivity: readable fonts, high contrast, spacing, no italics/all-caps */
    :root {
      --bg: #ffffff;
      --fg: #111111;
      --muted: #444;
      --accent: #005fcc;
      --ok: #116611;
      --warn: #b35a00;
      --err: #b00020;
      --surface: #f6f8fa;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--fg);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      line-height: 1.5;
    }
    header, footer {
      padding: 12px 16px;
      background: var(--surface);
      border-bottom: 1px solid #e5e7eb;
    }
    header h1 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    main {
      max-width: 900px;
      margin: 0 auto;
      padding: 16px;
      display: grid;
      grid-template-columns: 1fr 320px;
      gap: 16px;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
    }
    section#view {
      background: var(--surface);
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 16px;
    }
    .toolbar {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-bottom: 8px;
    }
    .toolbar button {
      padding: 8px 10px;
      font-size: 14px;
    }
    h2 {
      margin: 8px 0 8px;
      font-size: 1.2rem;
    }
    p, li { font-size: 1rem; }
    ul.bullets { padding-left: 20px; }
    label { display: block; margin: 10px 0 4px; font-weight: 600; }
    input[type="text"], input[type="email"], input[type="password"], input[type="number"] {
      width: 100%; padding: 10px 12px; border-radius: 6px; border: 1px solid #d1d5db; font-size: 1rem;
    }
    input:focus { outline: 3px solid #cfe6ff; border-color: var(--accent); }
    .row { display: flex; align-items: center; gap: 8px; }
    .actions { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      appearance: none; border: none; border-radius: 6px; padding: 10px 14px; background: var(--accent); color: #fff; cursor: pointer;
      font-size: 1rem; font-weight: 600;
    }
    button.secondary { background: #6b7280; }
    button.ghost { background: transparent; color: var(--accent); border: 1px solid var(--accent); }
    small.help { color: var(--muted); display: block; margin-top: 4px; }
    .msg { margin-top: 10px; padding: 10px; border-radius: 6px; }
    .msg.ok { background: #e7f7ea; color: var(--ok); border: 1px solid #c7ebcd; }
    .msg.err { background: #fde7ea; color: var(--err); border: 1px solid #f5c6cc; }
    .msg.info { background: #eef6ff; color: #0b5394; border: 1px solid #cfe6ff; }
    .hint { color: var(--muted); margin: 8px 0; }
    .checklist { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; }
    .checklist li { margin: 4px 0; }
    .okmark { color: var(--ok); }
    .warnmark { color: var(--warn); }
    .side {
      background: #0a0a0a; color: #e5e7eb; border-radius: 8px; padding: 12px; min-height: 200px;
    }
    .logs {
      background: #111; color: #9ef8b0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      border-radius: 6px; padding: 8px; height: 360px; overflow: auto; font-size: 12px;
    }
    a.link { color: var(--accent); text-decoration: underline; cursor: pointer; }
    .badge { display: inline-block; background: #eef6ff; color: #0b5394; border: 1px solid #cfe6ff; padding: 2px 6px; border-radius: 999px; font-size: 12px; margin-left: 6px;}
  </style>
  <script src="/app.js" defer></script>
</head>
<body>
  <header>
    <h1>University Portal — Password & Login Help <span class="badge">Demo</span></h1>
  </header>
  <main>
    <section id="view" aria-live="polite" aria-busy="false">
      <div class="toolbar">
        <button id="readAloudBtn" class="ghost" type="button">Read aloud</button>
        <button id="toLogin" class="ghost" type="button">Go to Login</button>
        <button id="toForgot" class="ghost" type="button">Forgot Password</button>
      </div>
      <div id="content">Loading…</div>
    </section>
    <aside class="side">
      <h2 style="margin-top:0">Logs</h2>
      <p class="hint">Simulated deliveries (codes & links) appear here. You can test without opening DevTools.</p>
      <div id="logs" class="logs" role="log" aria-live="polite"></div>
    </aside>
  </main>
  <footer>
    <small>Security: HTTPS only with HSTS; CSRF on all POST; CSP script-src 'self' (no inline scripts). Inclusive: plain language, clear steps, read-aloud.</small>
  </footer>
</body>
</html>`;
}

// ---------------------------- Client JS served at /app.js ----------------------------
// [Security: 2 - Injection (XSS)] No inline scripts; this external file is allowed by CSP script-src 'self'.
function clientJs(): string {
  return String.raw`(function(){
  "use strict";
  // [Security: 2 - XSS] All scripts are external (no inline). We never inject HTML from user input.
  // [Inclusivity] Console logs are mirrored to on-page panel.

  const $ = (sel, root=document) => root.querySelector(sel);
  const logsEl = $("#logs");
  const originalLog = console.log.bind(console);
  function log(){
    originalLog.apply(console, arguments);
    const args = Array.prototype.slice.call(arguments);
    const msg = args.map(a => {
      try { return typeof a === "string" ? a : JSON.stringify(a); } catch { return String(a); }
    }).join(" ");
    const line = document.createElement("div");
    const ts = new Date().toISOString().split("T")[1].replace("Z","");
    line.textContent = "["+ts+"] " + msg;
    logsEl.appendChild(line);
    logsEl.scrollTop = logsEl.scrollHeight;
  }
  console.log = log;

  // [Security: 1 - CSRF] Read CSRF token from meta tag and send as X-CSRF-Token on all sensitive POST requests.
  const metaCsrf = document.querySelector('meta[name="csrf-token"]');
  const CSRF = metaCsrf ? metaCsrf.getAttribute("content") || "" : "";

  const state = {
    lastResetToken: "",
    lastResetLink: "",
    lastMfaCode: "",
    mfaExpiresAt: 0,
    resetExpiresAt: 0
  };

  async function api(path, opts){
    const o = Object.assign({ method:"GET", headers: {} }, opts || {});
    o.headers["Content-Type"] = "application/json";
    if ((o.method || "GET").toUpperCase() === "POST") {
      o.headers["X-CSRF-Token"] = CSRF;
    }
    const res = await fetch(path, o);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { ok:false, message:"Bad response" }; }
    return { status: res.status, data };
  }

  // Router
  const view = $("#content");
  function navigate(hash){ location.hash = hash; }
  window.addEventListener("hashchange", render);
  $("#toLogin").addEventListener("click", ()=>navigate("#/login"));
  $("#toForgot").addEventListener("click", ()=>navigate("#/forgot"));

  // Read aloud
  const readBtn = $("#readAloudBtn");
  readBtn.addEventListener("click", () => {
    const synth = window.speechSynthesis;
    if (synth.speaking) { synth.cancel(); return; }
    const text = $("#content").innerText;
    const utter = new SpeechSynthesisUtterance(text);
    utter.rate = 1;
    synth.speak(utter);
  });

  function clear(el){ while (el.firstChild) el.removeChild(el.firstChild); }

  function labeledInput(labelText, type, id){
    const frag = document.createDocumentFragment();
    const label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = labelText;
    const input = document.createElement("input");
    input.type = type; input.id = id; input.autocomplete = "off";
    frag.appendChild(label); frag.appendChild(input);
    return {frag, input, label};
  }
  function mkBtn(text, cls){ const b = document.createElement("button"); b.type="button"; if (cls) b.className=cls; b.textContent=text; return b; }
  function help(text){ const s = document.createElement("small"); s.className="help"; s.textContent = text; return s; }
  function msg(text, kind){ const d = document.createElement("div"); d.className = "msg " + (kind || "info"); d.textContent = text; return d; }

  function addCopyButton(getText){
    const btn = mkBtn("Copy", "secondary");
    btn.addEventListener("click", async () => {
      try {
        const t = getText();
        await navigator.clipboard.writeText(t);
        log("Copied:", t);
      } catch (e) { log("Copy failed"); }
    });
    return btn;
  }

  function loginView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Sign in";
    view.appendChild(h2);
    const tips = document.createElement("ul"); tips.className="bullets";
    ["Use your email or username.", "Short steps. Clear feedback.", "If your password is expired, use Forgot Password."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; tips.appendChild(li); });
    view.appendChild(tips);

    const idRow = labeledInput("Email or username", "text", "identifier");
    const pwRow = labeledInput("Password", "password", "password");
    const showRow = document.createElement("div"); showRow.className="row";
    const showCb = document.createElement("input"); showCb.type="checkbox"; showCb.id="showpw";
    const showLb = document.createElement("label"); showLb.htmlFor="showpw"; showLb.textContent="Show password";
    showRow.appendChild(showCb); showRow.appendChild(showLb);

    view.appendChild(idRow.frag);
    view.appendChild(pwRow.frag);
    view.appendChild(showRow);
    view.appendChild(help("We never email passwords. Do not share codes."));

    const actions = document.createElement("div"); actions.className="actions";
    const btn = mkBtn("Sign in");
    const forgot = mkBtn("Forgot Password", "ghost");
    forgot.addEventListener("click", ()=>navigate("#/forgot"));
    actions.appendChild(btn); actions.appendChild(forgot);
    view.appendChild(actions);

    const area = document.createElement("div"); view.appendChild(area);

    showCb.addEventListener("change", ()=>{ pwRow.input.type = showCb.checked ? "text" : "password"; });

    btn.addEventListener("click", async () => {
      area.textContent = "";
      const identifier = idRow.input.value.trim();
      const password = pwRow.input.value;
      const res = await api("/api/login", { method:"POST", body: JSON.stringify({ identifier, password }) });
      const data = res.data || {};
      if (data.mfaRequired){
        state.lastMfaCode = data.code || "";
        state.mfaExpiresAt = data.expiresAt || 0;
        log("MFA code (simulated):", state.lastMfaCode, "expiresAt:", new Date(state.mfaExpiresAt).toLocaleTimeString());
        area.appendChild(msg("Additional check needed. Enter the 6-digit code.", "info"));
        navigate("#/mfa");
        return;
      }
      if (data.ok){
        area.appendChild(msg("Signed in.", "ok"));
        navigate("#/done");
      } else {
        area.appendChild(msg("Sign in failed. Please check details and try again.", "err"));
      }
    });
  }

  function forgotView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Reset your password";
    view.appendChild(h2);
    const bullets = document.createElement("ul"); bullets.className="bullets";
    ["Enter your email. We send a reset link and code.", "The link expires in about 10 minutes.", "You can paste the code manually if needed."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; bullets.appendChild(li); });
    view.appendChild(bullets);

    const emailRow = labeledInput("Your email", "email", "email");
    view.appendChild(emailRow.frag);
    view.appendChild(help("Example: name@school.edu"));

    const actions = document.createElement("div"); actions.className="actions";
    const sendBtn = mkBtn("Send reset link");
    const copyHow = addCopyButton(function(){ return "Steps: open your email, copy the code, come back here to Verify. If you can't open the link, paste the code manually."; });
    actions.appendChild(sendBtn); actions.appendChild(copyHow);
    view.appendChild(actions);

    const area = document.createElement("div"); view.appendChild(area);

    sendBtn.addEventListener("click", async () => {
      area.textContent="";
      const email = emailRow.input.value.trim();
      const res = await api("/api/reset/start", { method:"POST", body: JSON.stringify({ email }) });
      const data = res.data || {};
      if (data.ok){
        state.lastResetToken = data.token || "";
        state.resetExpiresAt = data.expiresAt || 0;
        const link = location.origin.replace("http:", "https:") + "/#/verify?token=" + encodeURIComponent(state.lastResetToken);
        state.lastResetLink = link;
        log("Reset link (simulated):", link);
        log("Reset token (simulated):", state.lastResetToken, "expiresAt:", new Date(state.resetExpiresAt).toLocaleTimeString());
        area.appendChild(msg("If the account exists, a reset link was sent. Check Logs panel.", "info"));
        const open = mkBtn("Open verification screen");
        open.addEventListener("click", ()=> navigate("#/verify?token=" + encodeURIComponent(state.lastResetToken)));
        area.appendChild(document.createElement("div")).appendChild(open);
      } else {
        area.appendChild(msg("If something went wrong, try again later.", "err"));
      }
    });
  }

  function verifyView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Verify your reset code";
    view.appendChild(h2);
    const tips = document.createElement("ul"); tips.className = "bullets";
    ["Paste the code from the link.", "If you opened the link directly, we check it here.", "Codes are single-use and short-lived."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; tips.appendChild(li); });
    view.appendChild(tips);

    const tokRow = labeledInput("Reset code", "text", "token");
    view.appendChild(tokRow.frag);
    const copyBtn = addCopyButton(function(){ return tokRow.input.value; });
    view.appendChild(copyBtn);

    const actions = document.createElement("div"); actions.className="actions";
    const previewBtn = mkBtn("Preview link");
    const confirmBtn = mkBtn("Confirm code");
    actions.appendChild(previewBtn); actions.appendChild(confirmBtn);
    view.appendChild(actions);

    const area = document.createElement("div"); view.appendChild(area);

    // Prefill from hash query if present
    const hash = location.hash || "";
    const qIndex = hash.indexOf("?token=");
    if (qIndex !== -1) {
      const token = decodeURIComponent(hash.substring(qIndex + 7));
      tokRow.input.value = token;
      // Read-only preview (does not modify session on server)
      (async ()=>{
        const r = await fetch("/api/reset/preview?token=" + encodeURIComponent(token), { method:"GET" });
        const data = await r.json().catch(function(){ return {}; });
        if (data && data.ok) area.appendChild(msg("Link is valid. You can confirm now.", "ok"));
        else area.appendChild(msg("The link may be invalid or expired.", "err"));
      })();
    }

    previewBtn.addEventListener("click", async ()=>{
      area.textContent="";
      const token = tokRow.input.value.trim();
      const r = await fetch("/api/reset/preview?token=" + encodeURIComponent(token), { method:"GET" });
      const data = await r.json().catch(function(){ return {}; });
      if (data && data.ok) area.appendChild(msg("Link is valid. You can confirm now.", "ok"));
      else area.appendChild(msg("The link may be invalid or expired.", "err"));
    });

    confirmBtn.addEventListener("click", async ()=>{
      area.textContent="";
      const token = tokRow.input.value.trim();
      const res = await api("/api/reset/verify", { method:"POST", body: JSON.stringify({ token }) });
      const data = res.data || {};
      if (data && data.ok){
        area.appendChild(msg("Code accepted. Create a new password.", "ok"));
        navigate("#/set-password");
      } else {
        area.appendChild(msg("We could not verify that code. Try again.", "err"));
      }
    });
  }

  function passwordView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Create a new password";
    view.appendChild(h2);
    const bullets = document.createElement("ul"); bullets.className="bullets";
    ["Use at least 10 characters.", "Include upper, lower, number, and a symbol.", "Take your time. No auto-timeout on this page."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; bullets.appendChild(li); });
    view.appendChild(bullets);

    const pwRow = labeledInput("New password", "password", "newpw");
    const pw2Row = labeledInput("Confirm password", "password", "confirmpw");
    view.appendChild(pwRow.frag);
    view.appendChild(pw2Row.frag);

    const showRow = document.createElement("div"); showRow.className="row";
    const show = document.createElement("input"); show.type="checkbox"; show.id="show2";
    const showL = document.createElement("label"); showL.htmlFor="show2"; showL.textContent="Show passwords";
    showRow.appendChild(show); showRow.appendChild(showL);
    view.appendChild(showRow);

    const checklist = document.createElement("ul"); checklist.className="checklist";
    const items = [
      { id:"len", text:"At least 10 characters" },
      { id:"low", text:"One lowercase" },
      { id:"upp", text:"One uppercase" },
      { id:"num", text:"One number" },
      { id:"sym", text:"One symbol (!@#$…)" },
      { id:"mat", text:"Passwords match" },
    ];
    const itemEls = {};
    items.forEach(function(it){
      const li = document.createElement("li");
      li.id = "rule-"+it.id;
      li.textContent = "• " + it.text;
      itemEls[it.id] = li;
      checklist.appendChild(li);
    });
    view.appendChild(checklist);

    function refreshChecks(){
      const p1 = pwRow.input.value || "";
      const p2 = pw2Row.input.value || "";
      const rules = {
        len: p1.length >= 10,
        low: /[a-z]/.test(p1),
        upp: /[A-Z]/.test(p1),
        num: /[0-9]/.test(p1),
        sym: /[^\w\s]/.test(p1),
        mat: p1.length>0 && p1 === p2
      };
      Object.keys(rules).forEach(function(k){
        const ok = rules[k];
        const el = itemEls[k];
        var base = el.textContent.replace(/^.? /,"");
        el.textContent = (ok ? "✓ " : "• ") + base;
        el.className = ok ? "okmark" : "warnmark";
      });
      return Object.keys(rules).every(function(k){ return rules[k]; });
    }
    pwRow.input.addEventListener("input", refreshChecks);
    pw2Row.input.addEventListener("input", refreshChecks);
    show.addEventListener("change", ()=> {
      const t = show.checked ? "text" : "password";
      pwRow.input.type = t; pw2Row.input.type = t;
    });

    const actions = document.createElement("div"); actions.className="actions";
    const setBtn = mkBtn("Save new password");
    const copyRules = addCopyButton(function(){ return "Password rules: at least 10 characters, include upper, lower, number, and a symbol."; });
    actions.appendChild(setBtn); actions.appendChild(copyRules);
    view.appendChild(actions);

    const area = document.createElement("div"); view.appendChild(area);

    setBtn.addEventListener("click", async ()=>{
      area.textContent="";
      if (!refreshChecks()){
        area.appendChild(msg("Please meet all rules before saving.", "err"));
        return;
      }
      const password = pwRow.input.value;
      const res = await api("/api/password/set", { method:"POST", body: JSON.stringify({ password }) });
      const data = res.data || {};
      if (data && data.ok){
        area.appendChild(msg("Password updated.", "ok"));
        navigate("#/done");
      } else {
        area.appendChild(msg(data && data.message ? data.message : "Could not set password.", "err"));
      }
    });
  }

  function mfaView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Two-step verification";
    view.appendChild(h2);
    const bullets = document.createElement("ul"); bullets.className="bullets";
    ["Enter the 6-digit code we sent.", "Codes expire quickly.", "Do not share codes with anyone."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; bullets.appendChild(li); });
    view.appendChild(bullets);

    const codeRow = labeledInput("6-digit code", "text", "mfacode");
    view.appendChild(codeRow.frag);
    const copyBtn = addCopyButton(function(){ return codeRow.input.value; });
    view.appendChild(copyBtn);

    const actions = document.createElement("div"); actions.className="actions";
    const verifyBtn = mkBtn("Verify");
    actions.appendChild(verifyBtn);
    view.appendChild(actions);

    const area = document.createElement("div"); view.appendChild(area);

    verifyBtn.addEventListener("click", async ()=>{
      area.textContent="";
      const code = (codeRow.input.value || "").trim();
      const res = await api("/api/mfa/verify", { method:"POST", body: JSON.stringify({ code }) });
      const data = res.data || {};
      if (data && data.ok){
        area.appendChild(msg("Verified.", "ok"));
        navigate("#/done");
      } else {
        area.appendChild(msg("That code didn't work. Try again.", "err"));
      }
    });
  }

  function doneView(){
    clear(view);
    const h2 = document.createElement("h2"); h2.textContent = "Portal";
    view.appendChild(h2);
    const p = document.createElement("p");
    p.textContent = "Welcome. Submission window is open.";
    view.appendChild(p);
    const bullets = document.createElement("ul"); bullets.className="bullets";
    ["Prepare your assignment file.", "Check course page for final instructions.", "Submit before the deadline."].forEach(function(t){ const li=document.createElement("li"); li.textContent=t; bullets.appendChild(li); });
    view.appendChild(bullets);
    const actions = document.createElement("div"); actions.className="actions";
    const back = mkBtn("Log out", "secondary");
    back.addEventListener("click", ()=> navigate("#/login"));
    actions.appendChild(back);
    view.appendChild(actions);
  }

  async function render(){
    const hash = location.hash || "#/login";
    if (hash.indexOf("#/forgot") === 0) forgotView();
    else if (hash.indexOf("#/verify") === 0) verifyView();
    else if (hash.indexOf("#/mfa") === 0) mfaView();
    else if (hash.indexOf("#/set-password") === 0) passwordView();
    else if (hash.indexOf("#/done") === 0) doneView();
    else loginView();
  }

  if (!location.hash) location.hash = "#/login";
  render();
})();`;
}

// ---------------------------- API Handlers ----------------------------
async function handleApi(req: Request, url: URL, session: Session): Promise<Response> {
  const path = url.pathname;

  // Helper: secure JSON response builder
  function json(data: any, status = 200): Response {
    const nonce = makeNonce();
    const headers = makeSecurityHeaders(nonce);
    headers.set("Content-Type", "application/json; charset=utf-8");
    headers.append("Set-Cookie", sessionCookie(session.id));
    return new Response(JSON.stringify(data), { status, headers });
  }

  // [Security: 1 - CSRF] Provide CSRF for SPA; also ensures session exists (kept for completeness)
  if (req.method === "GET" && path === "/api/csrf") {
    return json({ ok: true, csrf: session.csrf });
  }

  async function requireCsrf(): Promise<string | null> {
    const token = req.headers.get("X-CSRF-Token") || "";
    if (!token || token !== session.csrf) return null;
    return token;
  }

  // [Security: Identification & Authentication] Login (rate limited, bcrypt verify, generic messages)
  // [Security: 1 - CSRF] Protected by CSRF token
  if (req.method === "POST" && path === "/api/login") {
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "local";
    const body = await req.text();
    const data = parseJSON(body) || {};
    const identifier = sanitizeIdentifier(String(data.identifier || ""));
    const password = String(data.password || "");
    if (!await requireCsrf()) return json({ ok: false, message: "Invalid session. Refresh and try again." }, 403);

    const key = `login:${ip}:${identifier}`;
    if (rateLimited(key)) return json({ ok: false, message: "Please wait a moment and try again." }, 429);

    let user: User | null = null;
    const userId = userByEmail.get(identifier) || userByUsername.get(identifier);
    if (userId) user = users.get(userId) || null;

    // Always perform a verify to keep timing generic
    const fakeHash = await Bun.password.hash("not-the-password", { algorithm: "bcrypt", cost: 10 });
    const hash = user ? user.passwordHash : fakeHash;
    const verified = await Bun.password.verify(password, hash);

    if (!verified || !user) {
      return json({ ok: false, message: "Invalid login." }, 200);
    }

    // MFA flow
    if (user.mfaEnabled) {
      const code = generateDeterministicCode(session.id);
      const expiresAt = now() + 5 * 60_000;
      mfaCodes.set(session.id, { code, expiresAt, userId: user.id });
      // Do not expose PII; return code for testing and log in client console
      return json({ ok: true, mfaRequired: true, code, expiresAt, message: "MFA required" });
    } else {
      session.userId = user.id;
      session.authenticated = true;
      return json({ ok: true });
    }
  }

  // [Security: Identification & Authentication] MFA verify (rate limited)
  // [Security: 1 - CSRF] Protected by CSRF token
  if (req.method === "POST" && path === "/api/mfa/verify") {
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "local";
    if (!await requireCsrf()) return json({ ok: false, message: "Invalid session. Refresh and try again." }, 403);
    const body = await req.text();
    const data = parseJSON(body) || {};
    const code = sanitizeCode(String(data.code || "")).padStart(6,"0").slice(-6);
    const key = `mfa:${ip}:${session.id}`;
    if (rateLimited(key)) return json({ ok: false, message: "Please wait a moment and try again." }, 429);

    const entry = mfaCodes.get(session.id);
    if (!entry || now() > entry.expiresAt || entry.code !== code) {
      return json({ ok: false, message: "Invalid code." }, 200);
    }
    session.userId = entry.userId;
    session.authenticated = true;
    mfaCodes.delete(session.id);
    return json({ ok: true });
  }

  // [Security: Reset start] Always generic success, generate single-use token; store sink if unknown user
  // [Security: 1 - CSRF] Protected by CSRF token
  if (req.method === "POST" && path === "/api/reset/start") {
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "local";
    if (!await requireCsrf()) return json({ ok: false, message: "Invalid session. Refresh and try again." }, 403);
    const body = await req.text();
    const data = parseJSON(body) || {};
    const email = sanitizeEmail(String(data.email || ""));
    const key = `resetstart:${ip}:${email}`;
    if (rateLimited(key)) return json({ ok: true, message: "If the account exists, a reset email was sent." }, 200);

    const uid = userByEmail.get(email) || null;
    const token = randomId(24);
    const expiresAt = now() + 10 * 60_000;
    resetTokens.set(token, { token, userId: uid ?? null, createdAt: now(), expiresAt, used: false });

    // Return token for testing; client logs to browser console.
    return json({ ok: true, token, expiresAt, message: "If the account exists, a reset email was sent." });
  }

  // [Security: 1 - CSRF coverage] GET /api/reset/preview is read-only and does NOT modify session.
  // Only validates token and returns { ok, reason? }.
  if (req.method === "GET" && path === "/api/reset/preview") {
    const token = sanitizeCode(String(url.searchParams.get("token") || ""));
    const rec = resetTokens.get(token);
    let reason: string | undefined;
    if (!rec) reason = "invalid";
    else if (rec.used) reason = "used";
    else if (now() > rec.expiresAt) reason = "expired";
    if (reason) return json({ ok: false, reason }, 200);
    return json({ ok: true }, 200);
  }

  // [Security: Reset verify] Single-use token consumption; set session flag to allow password set
  // [Security: 1 - CSRF] Protected by CSRF token; requires { token } in POST body.
  if (req.method === "POST" && path === "/api/reset/verify") {
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "local";
    if (!await requireCsrf()) return json({ ok: false, message: "Invalid session. Refresh and try again." }, 403);
    const key = `resetverify:${ip}:${session.id}`;
    if (rateLimited(key)) return json({ ok: false, message: "Please wait and try again." }, 429);

    const body = await req.text();
    const data = parseJSON(body) || {};
    const token = sanitizeCode(String(data.token || ""));
    if (!token) return json({ ok: false, message: "Token is required." }, 400);

    const rec = resetTokens.get(token);
    if (!rec || rec.used || now() > rec.expiresAt) {
      return json({ ok: false, message: "Invalid code." }, 200);
    }
    // Consume token
    rec.used = true;
    resetTokens.set(token, rec);
    session.resetAllowed = true;
    session.resetUserId = rec.userId; // may be null to avoid user existence leak
    return json({ ok: true });
  }

  // [Security: Password set] Strong policy, requires reset context, bcrypt hashing
  // [Security: 1 - CSRF] Protected by CSRF token
  if (req.method === "POST" && path === "/api/password/set") {
    if (!await requireCsrf()) return json({ ok: false, message: "Invalid session. Refresh and try again." }, 403);
    if (!session.resetAllowed) return json({ ok: false, message: "Reset not verified. Start again." }, 400);

    const body = await req.text();
    const data = parseJSON(body) || {};
    const password = String(data.password || "");
    const issues = passwordPolicyIssues(password);
    if (issues.length > 0) {
      return json({ ok: false, message: "Password does not meet policy." }, 200);
    }

    // Save only if associated with a real user
    if (session.resetUserId) {
      const user = users.get(session.resetUserId);
      if (user) {
        const newHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
        user.passwordHash = newHash;
        users.set(user.id, user);
      }
    }
    // Invalidate context
    session.resetAllowed = false;
    session.resetUserId = undefined;
    return json({ ok: true });
  }

  // Unknown API
  return json({ ok: false, message: "Not found" }, 404);
}

// ---------------------------- Main request handler ----------------------------
async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);

  const cookies = getCookieMap(req);
  let session = getOrCreateSession(cookies["sid"]);
  let nonce = makeNonce();
  let headers = makeSecurityHeaders(nonce);
  headers.append("Set-Cookie", sessionCookie(session.id));

  // All API routes
  if (url.pathname.startsWith("/api/")) {
    return handleApi(req, url, session);
  }

  // Serve SPA JS from /app.js
  if (req.method === "GET" && url.pathname === "/app.js") {
    const js = clientJs();
    const h = makeSecurityHeaders(makeNonce());
    h.set("Content-Type", "application/javascript; charset=utf-8");
    h.append("Set-Cookie", sessionCookie(session.id));
    return new Response(js, { status: 200, headers: h });
  }

  // All GET routes serve the SPA HTML
  if (req.method === "GET") {
    const body = htmlPage(nonce, session.csrf);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(body, { status: 200, headers });
  }

  // Default: method not allowed
  return new Response("Method Not Allowed", { status: 405, headers });
}

// ---------------------------- Servers (HTTPS and HTTP->HTTPS redirect) ----------------------------
// [Security: HTTPS + HSTS] Enforce HTTPS; development uses provided certs.
// Start HTTPS on 3443
const httpsServer = Bun.serve({
  port: 3443,
  cert: Bun.file(CERT_PATH),
  key: Bun.file(KEY_PATH),
  reusePort: true,
  idleTimeout: 60,
  fetch: handleRequest,
});

// Start HTTP on 3000 that redirects to HTTPS
const httpServer = Bun.serve({
  port: 3000,
  reusePort: true,
  fetch(req: Request) {
    const url = new URL(req.url);
    const location = `https://localhost:3443${url.pathname}${url.search}`;
    return new Response(null, { status: 301, headers: { Location: location } });
  },
});

// Log start (appears in server console; browser console is handled inside the SPA)
console.log(`HTTPS server running on https://localhost:3443  (HTTP redirect on http://localhost:3000)`);

// -----------------------------------------------------------------------------------------------
// Notes mapping to Requirements:
// - Inclusivity: clear language, bullet points, high contrast; Read Aloud and Copy buttons in views.
// - Security: 1 (Broken Access Control & CSRF) - Per-session CSRF token is embedded in a meta tag and required on all sensitive POST routes (/api/login, /api/mfa/verify, /api/reset/start, /api/reset/verify, /api/password/set).
// - Security: 2 (Injection/XSS) - No inline scripts or inline handlers; CSP sets script-src 'self'; DOM uses textContent and sanitized inputs.
// - Security: Passwords hashed with bcrypt via Bun.password; strong policy enforced.
// - Security: MFA flow with deterministic 6-digit code per-session; logged to browser console for testing.
// - Security: Reset tokens are random, single-use, short-lived. GET /api/reset/preview is read-only, POST /api/reset/verify consumes token and sets session verification.
// - Security: Rate limiting for login and reset; generic error messages to avoid info leaks.
// - Privacy: No PII in responses beyond necessary, no exposure of usernames; tokens/codes only in console logs.
// - SSRF/Open Redirect: No external redirects; ignore any next/redirect usage; only internal hash routes.
// - SPA: Single file, no external assets; all routes functional within hash router.
// -----------------------------------------------------------------------------------------------
