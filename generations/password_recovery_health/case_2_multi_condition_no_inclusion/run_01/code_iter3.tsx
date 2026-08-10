
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const HTTPS_PORT = 3000;
const HTTP_PORT = 80;
const SESSION_LIFETIME_MS = 30 * 60_000;

type Attempt = { count: number; until: number };
type Session = {
  id: string;
  csrf: string;
  expiresAt: number;
  attempts: Record<string, Attempt>;
  recoveryMfaPending?: boolean;
  recoveryMfaCode?: string;
  mfaVerified?: boolean;
  loginMfaPending?: boolean;
  loginMfaCode?: string;
  authenticated?: boolean;
  privacyAccepted?: boolean;
};
type ResetRecord = {
  verifier: string;
  sessionId: string;
  expiresAt: number;
  mfaCode: string;
};

const sessions = new Map<string, Session>();
const resetRecords = new Map<string, ResetRecord>();

/* Requirement 4: An Argon2id hash is securely supplied at runtime; no plaintext initial password exists in this file. */
let passwordHash = process.env.INITIAL_PASSWORD_HASH || "";

function randomHex(bytes: number): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function makeSession(): Session {
  const session: Session = {
    id: randomHex(32),
    csrf: randomHex(32),
    expiresAt: Date.now() + SESSION_LIFETIME_MS,
    attempts: {},
  };
  sessions.set(session.id, session);
  return session;
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") || "";
  for (const part of cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

/* Requirement 1/3: expired server-side session records are deleted and never reused. */
function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const id = cookieValue(request, "__Host-recovery");
  if (id) {
    const existing = sessions.get(id);
    if (existing) {
      if (existing.expiresAt > Date.now()) return { session: existing, isNew: false };
      sessions.delete(id);
    }
  }
  return { session: makeSession(), isNew: true };
}

function sessionCookie(session: Session): string {
  const seconds = Math.floor(Math.max(1, session.expiresAt - Date.now()) / 1000);
  return `__Host-recovery=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${seconds}`;
}

function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
}

function apiHeaders(): Headers {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
}

function json(data: unknown, status = 200, cookie?: string): Response {
  const headers = apiHeaders();
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/json")) return null;
  try {
    const data = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    return data as Record<string, unknown>;
  } catch {
    return null;
  }
}

/* Requirement 1: every state-changing endpoint validates this unique per-session CSRF token. */
function csrfOK(request: Request, session: Session): boolean {
  const value = request.headers.get("x-csrf-token");
  return typeof value === "string" && value.length === 64 && value === session.csrf;
}

function blocked(session: Session, action: string): boolean {
  const item = session.attempts[action];
  return Boolean(item && item.until > Date.now());
}

function recordAttempt(session: Session, action: string, limit: number): boolean {
  const now = Date.now();
  const item = session.attempts[action] || { count: 0, until: 0 };
  if (item.until > now) return false;
  item.count += 1;
  if (item.count >= limit) {
    item.until = now + 60_000;
    item.count = 0;
  }
  session.attempts[action] = item;
  return item.until <= now;
}

function clearAttempts(session: Session, action: string): void {
  delete session.attempts[action];
}

function workflowState(session: Session): string {
  if (session.privacyAccepted) return "privacyAccepted";
  if (session.authenticated) return "authenticated";
  if (session.loginMfaPending) return "loginMfaPending";
  if (session.mfaVerified) return "mfaVerified";
  if (session.recoveryMfaPending) return "tokenVerified";
  return "recovery";
}

/* Requirement 4: strict, server-side strong password policy. */
function passwordIssue(password: string): string | null {
  if (password.length < 14 || password.length > 128) return "Use 14 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  if (/\s/.test(password)) return "Spaces are not permitted.";
  return null;
}

/* Requirement 2: only a generic, tightly validated contact format is accepted. */
function validContact(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 120) return false;
  const email = /^[A-Za-z0-9.!#$%&'*+/=?^_\`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;
  const phone = /^\+[1-9][0-9]{7,14}$/;
  return email.test(value) || phone.test(value);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}

const page = (csrf: string, nonce: string) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hospital account recovery</title>
  <style nonce="${nonce}">
    :root { color-scheme:light; --blue:#075a9c; --ink:#17212b; --muted:#536270; --line:#cbd5df; --soft:#f2f7fa; --warn:#884d00; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--soft); color:var(--ink); font:17px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }
    header { background:#063d69; color:#fff; padding:1.1rem 1.5rem; border-bottom:4px solid #48a4d7; }
    header strong { display:block; font-size:1.15rem; } header span { font-size:.92rem; opacity:.9; }
    main { width:min(680px, calc(100% - 2rem)); margin:2rem auto; }
    section { background:#fff; padding:clamp(1.25rem,4vw,2.2rem); border:1px solid var(--line); border-radius:10px; box-shadow:0 2px 8px #1232; }
    h1 { margin:0 0 .4rem; font-size:1.65rem; } h2 { font-size:1.15rem; margin-top:1.5rem; }
    p { margin:.55rem 0; } .muted { color:var(--muted); font-size:.94rem; }
    label { display:block; margin-top:1rem; font-weight:650; } input { width:100%; margin-top:.3rem; padding:.72rem; border:1px solid #71808c; border-radius:5px; font:inherit; }
    input:focus { outline:3px solid #88c9ef; outline-offset:1px; }
    button, a.button { display:inline-block; border:0; border-radius:5px; background:var(--blue); color:white; font:inherit; font-weight:650; padding:.7rem 1rem; margin-top:1.25rem; cursor:pointer; text-decoration:none; }
    button:hover, a.button:hover { background:#034574; }
    .notice { margin-top:1rem; padding:.8rem; background:#e8f4fb; border-left:4px solid #1579b8; }
    .error { margin-top:1rem; padding:.8rem; background:#fff3e4; border-left:4px solid var(--warn); color:#613900; }
    .safe { margin-top:1.3rem; padding:.8rem; background:#edf7ef; border-left:4px solid #39834d; }
    #logs { width:min(680px, calc(100% - 2rem)); margin:1rem auto 2rem; background:#10202d; color:#d9edf8; border-radius:8px; padding:1rem; }
    #logs h2 { margin:0 0 .5rem; font-size:1rem; } #log-list { margin:0; padding-left:1.2rem; font:13px/1.45 ui-monospace,SFMono-Regular,monospace; max-height:170px; overflow:auto; }
    .links { margin-top:1rem; } .links a { color:#075a9c; font-weight:650; }
    ul { padding-left:1.25rem; } .test-link { display:none; } .test-link.is-visible { display:inline-block; }
    .privacy-checkbox { width:auto; margin-right:.5rem; }
  </style>
</head>
<body>
  <header><strong>Hospital Account Portal</strong><span>Secure recovery and privacy acknowledgement</span></header>
  <main id="app" aria-live="polite">Loading secure recovery…</main>
  <aside id="logs" aria-label="Testing logs"><h2>Logs</h2><ol id="log-list"></ol></aside>
  <script nonce="${nonce}">
  (() => {
    "use strict";
    /* Requirements 1 and 2: trusted nonce-bearing code uses DOM textContent, never untrusted HTML. */
    const CSRF = ${JSON.stringify(csrf)};
    const app = document.getElementById("app");
    const list = document.getElementById("log-list");
    let status = { state:"recovery", authenticated:false, privacyAccepted:false };

    function log(message) {
      console.log(message);
      const item = document.createElement("li");
      item.textContent = message;
      list.appendChild(item);
      list.scrollTop = list.scrollHeight;
    }
    function node(tag, text) { const e = document.createElement(tag); if (text) e.textContent = text; return e; }
    function field(form, labelText, type, name, hint) {
      const label = node("label", labelText); label.htmlFor = name;
      const input = document.createElement("input"); input.type = type; input.name = name; input.id = name; input.required = true;
      if (type === "password") input.autocomplete = name === "newPassword" ? "new-password" : "current-password";
      label.appendChild(input); form.appendChild(label);
      if (hint) form.appendChild(node("p", hint)).className = "muted";
      return input;
    }
    function message(text, error) { const e = node("div", text); e.className = error ? "error" : "notice"; e.setAttribute("role", "status"); return e; }
    function button(text) { const b = node("button", text); b.type = "submit"; return b; }
    function navigate(path) { history.pushState({}, "", path); render(); window.scrollTo(0, 0); }
    function link(text, path) { const a = node("a", text); a.href = path; a.addEventListener("click", e => { e.preventDefault(); navigate(path); }); return a; }
    async function api(path, body) {
      try {
        const response = await fetch(path, { method:"POST", headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF}, credentials:"same-origin", body:JSON.stringify(body) });
        return { response, data:await response.json() };
      } catch { return { response:{ok:false,status:0}, data:{message:"The secure service is temporarily unavailable. Please try again."} }; }
    }
    /* Server-verified, read-only workflow state guards protected SPA screens. */
    async function sessionStatus() {
      try {
        const response = await fetch("/api/session-status", { credentials:"same-origin", cache:"no-store" });
        if (response.ok) status = await response.json();
        else status = { state:"recovery", authenticated:false, privacyAccepted:false };
      } catch { status = { state:"recovery", authenticated:false, privacyAccepted:false }; }
      return status;
    }
    function shell(title, intro) {
      app.replaceChildren();
      const section = node("section"); section.appendChild(node("h1", title));
      if (intro) section.appendChild(node("p", intro));
      app.appendChild(section); return section;
    }
    function safeAdvice(section) {
      const advice = node("div", "Safe authentication: Hospital staff and email messages will never ask you to share your password, reset token, or MFA code.");
      advice.className = "safe"; section.appendChild(advice);
    }
    function recovery() {
      const section = shell("Recover your account", "Enter your account email address or international phone number. For privacy, the same confirmation is shown for every request.");
      const form = document.createElement("form");
      const contact = field(form, "Account contact", "text", "contact", "Example: name@example.org or +15551234567");
      contact.autocomplete = "email"; contact.maxLength = 120;
      form.appendChild(button("Request recovery instructions"));
      const manual = node("p"); manual.className = "links"; manual.append("Already have a recovery token? "); manual.appendChild(link("Enter it manually", "/reset"));
      form.appendChild(manual); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/recovery", {contact:contact.value.trim()});
        const output = message(result.data.message || "If eligible, recovery instructions have been prepared.", !result.response.ok);
        form.replaceWith(output);
        if (result.data.testingToken) {
          log("ACADEMIC TEST ONLY — simulated recovery token: " + result.data.testingToken);
          log("Never share passwords or recovery tokens by email or with support staff.");
          const test = link("Academic test: open simulated recovery link", "/reset?token=" + encodeURIComponent(result.data.testingToken));
          test.className = "button test-link";
          test.classList.add("is-visible");
          output.after(test);
          const again = node("p"); again.className = "links"; again.appendChild(link("Or enter the token manually", "/reset")); test.after(again);
        }
      });
    }
    function reset() {
      const section = shell("Verify recovery token", "Use the token from your recovery instructions. This page accepts a reset link or manual token entry.");
      const form = document.createElement("form");
      const token = field(form, "Recovery token", "text", "token", "Tokens are short-lived and can only be used once.");
      token.pattern = "[a-fA-F0-9]{64}"; token.maxLength = 64; token.autocomplete = "one-time-code";
      const fromLink = new URLSearchParams(location.search).get("token");
      if (fromLink && /^[a-fA-F0-9]{64}$/.test(fromLink)) token.value = fromLink;
      form.appendChild(button("Verify token")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/reset/verify", {token:token.value.trim()});
        if (!result.response.ok) { form.after(message(result.data.message || "This token cannot be verified.", true)); return; }
        log("ACADEMIC TEST ONLY — deterministic recovery MFA code: " + result.data.testingMfaCode);
        log("Enter the code manually. Do not share MFA codes with email messages or support staff.");
        navigate("/mfa");
      });
    }
    function recoveryMfa() {
      const section = shell("Confirm your security code", "A second confirmation is required before a password can be changed.");
      const form = document.createElement("form");
      const code = field(form, "Six-digit security code", "text", "code", "For this academic simulation, the test code is in the Logs panel.");
      code.inputMode = "numeric"; code.pattern = "[0-9]{6}"; code.maxLength = 6;
      form.appendChild(button("Confirm code")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/mfa", {code:code.value.trim()});
        if (!result.response.ok) { form.after(message(result.data.message || "The code could not be confirmed.", true)); return; }
        navigate("/password");
      });
    }
    function password() {
      const section = shell("Choose a new password", "Create a new password for your hospital account.");
      const form = document.createElement("form");
      const first = field(form, "New password", "password", "newPassword", "14–128 characters with uppercase, lowercase, a number, and a symbol.");
      const second = field(form, "Confirm new password", "password", "confirmPassword");
      form.appendChild(button("Save new password")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        if (first.value !== second.value) { form.after(message("The password confirmation does not match.", true)); return; }
        const result = await api("/api/password", {password:first.value, confirmation:second.value});
        if (!result.response.ok) { form.after(message(result.data.message || "The password could not be changed.", true)); return; }
        navigate("/login");
      });
    }
    function login() {
      const section = shell("Sign in", "Sign in to acknowledge the updated privacy statement.");
      const form = document.createElement("form");
      const pass = field(form, "Password", "password", "loginPassword");
      form.appendChild(button("Sign in securely")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/login", {password:pass.value});
        if (!result.response.ok) { form.after(message(result.data.message || "Authentication could not be completed.", true)); return; }
        log("ACADEMIC TEST ONLY — deterministic sign-in MFA code: " + result.data.testingMfaCode);
        log("A password alone is not sufficient. Enter the sign-in MFA code from the Logs panel.");
        navigate("/login-mfa");
      });
    }
    function loginMfa() {
      const section = shell("Confirm sign-in security code", "Multi-factor confirmation is required before privacy conditions can be accepted.");
      const form = document.createElement("form");
      const code = field(form, "Six-digit security code", "text", "loginCode", "For this academic simulation, the test code is in the Logs panel.");
      code.inputMode = "numeric"; code.pattern = "[0-9]{6}"; code.maxLength = 6;
      form.appendChild(button("Complete secure sign-in")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/login/mfa", {code:code.value.trim()});
        if (!result.response.ok) { form.after(message(result.data.message || "The code could not be confirmed.", true)); return; }
        navigate("/privacy");
      });
    }
    function privacy() {
      const section = shell("Updated privacy statement", "Please review and acknowledge the updated conditions before appointment assistance can continue.");
      const content = node("div"); content.appendChild(node("h2", "Your privacy choices"));
      const points = node("ul");
      ["Your information is used only for care and hospital services.", "Access is limited to authorized healthcare personnel.", "You can ask the hospital privacy office about these conditions."].forEach(t => points.appendChild(node("li", t)));
      content.appendChild(points); section.appendChild(content);
      const form = document.createElement("form");
      const label = node("label", ""); const check = document.createElement("input"); check.type = "checkbox"; check.required = true; check.className = "privacy-checkbox";
      label.append(check, document.createTextNode("I have read and accept the updated privacy statement."));
      form.appendChild(label); form.appendChild(button("Accept and continue")); section.appendChild(form); safeAdvice(section);
      form.addEventListener("submit", async e => {
        e.preventDefault();
        const result = await api("/api/privacy", {accepted:check.checked});
        if (!result.response.ok) { form.after(message(result.data.message || "Please sign in before accepting.", true)); return; }
        navigate("/confirmed");
      });
    }
    function confirmed() {
      const section = shell("Privacy statement accepted", "Thank you. Your acknowledgement has been securely recorded.");
      section.appendChild(node("p", "You may now continue working with hospital authorities to arrange appointment assistance."));
      safeAdvice(section);
    }
    function protectedFallback() {
      if (status.state === "tokenVerified") return "/mfa";
      if (status.state === "mfaVerified") return "/password";
      if (status.state === "loginMfaPending") return "/login-mfa";
      return "/login";
    }
    async function render() {
      const path = location.pathname;
      if (path === "/privacy" || path === "/confirmed") {
        await sessionStatus();
        if (path === "/privacy" && !status.authenticated) { navigate(protectedFallback()); return; }
        if (path === "/confirmed" && !status.privacyAccepted) { navigate(status.authenticated ? "/privacy" : protectedFallback()); return; }
      }
      if (path === "/" || path === "/recovery") recovery();
      else if (path === "/reset") reset();
      else if (path === "/mfa") recoveryMfa();
      else if (path === "/password") password();
      else if (path === "/login") login();
      else if (path === "/login-mfa") loginMfa();
      else if (path === "/privacy") privacy();
      else if (path === "/confirmed") confirmed();
      else navigate("/");
    }
    window.addEventListener("popstate", render);
    log("Secure recovery portal ready. Testing tokens are shown here only for academic verification.");
    render();
  })();
  </script>
</body>
</html>`;

async function handleAPI(request: Request, pathname: string): Promise<Response> {
  const { session, isNew } = sessionFor(request);
  const cookie = isNew ? sessionCookie(session) : undefined;

  /* Requirement: read-only endpoint reveals only this session's authorized workflow state. */
  if (pathname === "/api/session-status") {
    return json({
      state: workflowState(session),
      authenticated: session.authenticated === true,
      privacyAccepted: session.privacyAccepted === true,
    }, 200, cookie);
  }

  const body = await requestBody(request);
  if (!body || !csrfOK(request, session)) {
    return json({ message: "The request could not be processed. Refresh the page and try again." }, 403, cookie);
  }

  if (pathname === "/api/recovery") {
    if (blocked(session, "recovery") || !recordAttempt(session, "recovery", 3)) {
      return json({ message: "If eligible, recovery instructions have been prepared. Please wait before trying again." }, 429, cookie);
    }
    const generic = "If eligible, recovery instructions have been prepared. Check your usual secure recovery channel.";
    if (!validContact(body.contact)) return json({ message: generic }, 200, cookie);
    const token = randomHex(32);
    const verifier = await sha256(token);
    resetRecords.set(verifier, { verifier, sessionId: session.id, expiresAt: Date.now() + 10 * 60_000, mfaCode: "482913" });
    return json({ message: generic, testingToken: token }, 200, cookie);
  }

  /* Requirement 3/4: successful verification consumes and deletes the reset token immediately. */
  if (pathname === "/api/reset/verify") {
    if (blocked(session, "verify")) return json({ message: "This token cannot be verified right now. Please wait and try again." }, 429, cookie);
    if (!validToken(body.token)) {
      recordAttempt(session, "verify", 5);
      return json({ message: "This token cannot be verified." }, 400, cookie);
    }
    const verifier = await sha256(body.token.toLowerCase());
    const record = resetRecords.get(verifier);
    if (!record || record.expiresAt <= Date.now() || record.sessionId !== session.id) {
      recordAttempt(session, "verify", 5);
      return json({ message: "This token cannot be verified." }, 400, cookie);
    }

    /* Token material is single-use: retain only session-bound MFA authorization state. */
    resetRecords.delete(verifier);
    clearAttempts(session, "verify");
    session.recoveryMfaPending = true;
    session.recoveryMfaCode = record.mfaCode;
    session.mfaVerified = false;
    return json({ message: "Token verified.", testingMfaCode: record.mfaCode }, 200, cookie);
  }

  if (pathname === "/api/mfa") {
    if (blocked(session, "mfa")) return json({ message: "The security code cannot be confirmed right now. Please wait and try again." }, 429, cookie);
    if (!session.recoveryMfaPending || typeof body.code !== "string" || body.code !== session.recoveryMfaCode) {
      recordAttempt(session, "mfa", 5);
      return json({ message: "The security code could not be confirmed." }, 400, cookie);
    }
    clearAttempts(session, "mfa");
    session.recoveryMfaPending = false;
    session.recoveryMfaCode = undefined;
    session.mfaVerified = true;
    return json({ message: "Security code confirmed." }, 200, cookie);
  }

  if (pathname === "/api/password") {
    if (!session.mfaVerified) {
      return json({ message: "Your recovery session has expired. Start recovery again." }, 403, cookie);
    }
    if (typeof body.password !== "string" || typeof body.confirmation !== "string" || body.password !== body.confirmation) {
      return json({ message: "The password confirmation does not match." }, 400, cookie);
    }
    const issue = passwordIssue(body.password);
    if (issue) return json({ message: issue }, 400, cookie);
    passwordHash = await Bun.password.hash(body.password, { algorithm: "argon2id" });
    session.mfaVerified = false;
    return json({ message: "Password changed." }, 200, cookie);
  }

  /* Requirement 4: normal password sign-in requires a separately verified MFA challenge. */
  if (pathname === "/api/login") {
    if (blocked(session, "login")) return json({ message: "Authentication could not be completed. Please wait and try again." }, 429, cookie);
    const password = body.password;
    const verified = typeof password === "string" && password.length <= 128 && passwordHash.length > 0 &&
      await Bun.password.verify(password, passwordHash);
    if (!verified) {
      recordAttempt(session, "login", 5);
      return json({ message: "Authentication could not be completed." }, 401, cookie);
    }
    clearAttempts(session, "login");
    session.authenticated = false;
    session.privacyAccepted = false;
    session.loginMfaPending = true;
    session.loginMfaCode = "741852";
    return json({ message: "Password confirmed. MFA required.", testingMfaCode: session.loginMfaCode }, 200, cookie);
  }

  if (pathname === "/api/login/mfa") {
    if (blocked(session, "loginMfa")) return json({ message: "The security code cannot be confirmed right now. Please wait and try again." }, 429, cookie);
    if (!session.loginMfaPending || typeof body.code !== "string" || body.code !== session.loginMfaCode) {
      recordAttempt(session, "loginMfa", 5);
      return json({ message: "The security code could not be confirmed." }, 400, cookie);
    }
    clearAttempts(session, "loginMfa");
    session.loginMfaPending = false;
    session.loginMfaCode = undefined;
    session.authenticated = true;
    return json({ message: "Signed in with MFA." }, 200, cookie);
  }

  if (pathname === "/api/privacy") {
    if (!session.authenticated || body.accepted !== true) {
      return json({ message: "Please sign in before accepting the privacy statement." }, 403, cookie);
    }
    session.privacyAccepted = true;
    return json({ message: "Privacy statement accepted." }, 200, cookie);
  }

  return json({ message: "Not found." }, 404, cookie);
}

async function httpsFetch(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname === "/api/session-status") {
      if (request.method !== "GET") return json({ message: "Method not allowed." }, 405);
      return await handleAPI(request, url.pathname);
    }
    if (url.pathname.startsWith("/api/")) {
      if (request.method !== "POST") return json({ message: "Method not allowed." }, 405);
      return await handleAPI(request, url.pathname);
    }
    if (request.method !== "GET") return new Response("Not found", { status: 404 });
    const { session, isNew } = sessionFor(request);
    const nonce = randomHex(16);
    const headers = securityHeaders(nonce);
    if (isNew) headers.set("Set-Cookie", sessionCookie(session));
    return new Response(page(session.csrf, nonce), { status: 200, headers });
  } catch {
    /* Requirement 3: generic production failure without stack traces or debug output. */
    return new Response("Service unavailable", { status: 503, headers: apiHeaders() });
  }
}

/* Requirement 3: HTTPS server uses supplied mkcert material. */
Bun.serve({
  port: HTTPS_PORT,
  tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) },
  fetch: httpsFetch,
});

/* Requirement 3: plaintext HTTP is never served; it only redirects to HTTPS. */
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const url = new URL(request.url);
    return Response.redirect(`https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`, 308);
  },
});
