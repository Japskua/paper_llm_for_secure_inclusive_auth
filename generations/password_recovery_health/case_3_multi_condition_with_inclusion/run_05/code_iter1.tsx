
import { createHash, randomBytes } from "crypto";

// Requirements: HTTPS/security configuration. This server intentionally listens only with TLS.
// Plain HTTP requests cannot establish a connection to this TLS-only listener.
const PORT = Number(process.env.PORT || 3000);
const CERT_FILE = Bun.file("certs/cert.pem");
const KEY_FILE = Bun.file("certs/key.pem");

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryTokenHash?: string;
  recoveryVerified?: boolean;
  pendingMfa?: boolean;
  authenticated?: boolean;
  privacyAccepted?: boolean;
};

type ResetRecord = {
  tokenHash: string;
  accountKey: string;
  expiresAt: number;
  used: boolean;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
const rateWindows = new Map<string, number[]>();

// Requirements: passwords are always stored as a Bun bcrypt hash, never plaintext.
let accountPasswordHash = await Bun.password.hash("Initial!Hospital2026", {
  algorithm: "bcrypt",
  cost: 10,
});
const DEMO_ACCOUNT_KEY = "internal-demo-account";
const MFA_CODE = "246810";
const SESSION_MAX_AGE = 60 * 60 * 8;
const RESET_LIFETIME = 15 * 60 * 1000;

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const entry of cookie.split(";")) {
    const index = entry.indexOf("=");
    if (index > 0) {
      result[entry.slice(0, index).trim()] = decodeURIComponent(entry.slice(index + 1).trim());
    }
  }
  return result;
}

// Requirements: per-session cryptographically random CSRF token and secure cookie session.
function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const sid = parseCookies(request).hospital_session;
  if (sid && sessions.has(sid)) {
    return { session: sessions.get(sid)!, isNew: false };
  }
  const session: Session = {
    id: randomToken(32),
    csrf: randomToken(32),
    createdAt: Date.now(),
  };
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function secureHeaders(nonce: string, session?: Session, newSession = false): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  });
  if (newSession && session) {
    headers.append(
      "Set-Cookie",
      `hospital_session=${encodeURIComponent(session.id)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
    );
  }
  return headers;
}

function json(
  value: Record<string, unknown>,
  nonce: string,
  session?: Session,
  newSession = false,
  status = 200,
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: secureHeaders(nonce, session, newSession),
  });
}

function genericError(
  message: string,
  nonce: string,
  session: Session,
  newSession: boolean,
  status = 400,
): Response {
  return json({ ok: false, message }, nonce, session, newSession, status);
}

// Requirements: rate limiting applies to login, token checking, and password update.
function rateAllowed(key: string, maximum: number, periodMs: number): { allowed: boolean; retry: number } {
  const now = Date.now();
  const recent = (rateWindows.get(key) || []).filter((time) => now - time < periodMs);
  if (recent.length >= maximum) {
    rateWindows.set(key, recent);
    return { allowed: false, retry: Math.max(1, Math.ceil((periodMs - (now - recent[0])) / 1000)) };
  }
  recent.push(now);
  rateWindows.set(key, recent);
  return { allowed: true, retry: 0 };
}

// Requirements: input validation/sanitisation. Values are never reflected into HTML.
function validIdentifier(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  return normalized.length >= 3 && normalized.length <= 120 && /^[A-Za-z0-9@._+\- ]+$/.test(normalized);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{20,120}$/.test(value);
}

function passwordPolicy(password: unknown): string | null {
  if (typeof password !== "string") return "Please enter a password.";
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Please use 128 characters or fewer.";
  if (/\s/.test(password)) return "Please do not use spaces in this password.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Include an uppercase letter, lowercase letter, number, and symbol.";
  }
  return null;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// Requirements: CSRF/access-control validation for every state-changing API route.
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length > 0 && supplied === session.csrf;
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--navy:#12324a;--blue:#176b9d;--pale:#edf6fa;--line:#c8d8e1;--ink:#17232b;--good:#126943;--warn:#8a4a00;--bad:#a22525}
*{box-sizing:border-box}body{margin:0;background:#f6f9fa;color:var(--ink);font:18px/1.5 Arial,Helvetica,sans-serif}
header{background:var(--navy);color:white;padding:1rem 1.4rem}header .brand{font-size:1.25rem;font-weight:700}header p{margin:.15rem 0 0;font-size:.92rem}
main{max-width:1040px;margin:0 auto;padding:1.4rem;display:grid;grid-template-columns:245px minmax(0,1fr);gap:1.4rem}
aside,section,.card{background:white;border:1px solid var(--line);border-radius:10px;padding:1.15rem;box-shadow:0 1px 2px #12253512}
h1{font-size:1.7rem;line-height:1.2;margin:0 0 .6rem}h2{font-size:1.2rem;margin:.2rem 0 .65rem}h3{font-size:1rem;margin:.2rem 0 .4rem}
p{margin:.45rem 0 1rem}.steps{list-style:none;padding:0;margin:.5rem 0}.steps li{padding:.5rem;border-left:5px solid #cedae0;margin:.3rem 0;color:#52636c}.steps li.active{border-color:var(--blue);background:var(--pale);color:var(--ink);font-weight:700}.steps li.done{border-color:var(--good);color:var(--good)}
label{display:block;font-weight:700;margin-top:.85rem}input{display:block;width:100%;max-width:520px;padding:.7rem;border:2px solid #8097a3;border-radius:6px;font-size:1rem;margin-top:.25rem}input:focus,button:focus,a:focus{outline:3px solid #f1b43b;outline-offset:2px}
button,.button-link{display:inline-block;margin:.9rem .55rem 0 0;background:var(--blue);color:white;border:0;border-radius:6px;padding:.7rem 1rem;font-size:1rem;font-weight:700;cursor:pointer;text-decoration:none}.secondary{background:white;color:var(--navy);border:2px solid var(--blue)}.quiet{background:#536771}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .85rem;margin:.8rem 0}.success{border-color:var(--good);background:#ecf8f1}.warning{border-color:var(--warn);background:#fff6e8}.error{border-color:var(--bad);background:#fff0f0}.small{font-size:.92rem}.help{margin-top:1rem;background:#fff9e9}.logs{margin-top:1rem;background:#10232e;color:#e3f7ff;border-radius:7px;padding:.65rem;max-height:175px;overflow:auto;font:13px/1.4 monospace;white-space:pre-wrap}.muted{color:#52636c}.policy{padding-left:1.2rem}.policy li{margin:.25rem 0}@media(max-width:760px){main{display:block;padding:1rem}aside{margin-bottom:1rem}}
</style>
</head>
<body>
<header><div class="brand">Hospital secure account portal</div><p>Check that the address begins with <strong>https://localhost</strong>. We never ask for a password or code by email or phone.</p></header>
<main>
<aside aria-label="Recovery progress">
<h2>Your progress</h2><ol class="steps" id="steps"></ol>
<button class="secondary" id="pauseButton" type="button">Pause and return later</button>
<p class="small muted">There is no countdown. Your secure session keeps your place.</p>
</aside>
<section aria-live="polite">
<div id="content"></div>
<div class="card help">
<h2>Help and safe sign-in</h2>
<p>If anything feels unclear, pause here. You can return without starting over in this browser.</p>
<p class="small">Only enter your password and one-time code on this hospital page. Hospital staff will never ask you to read a password or recovery code aloud.</p>
<button class="secondary" id="helpButton" type="button">Show a short reminder</button>
<div id="helpMessage" class="notice" hidden></div>
</div>
<h2 class="small">Activity logs for this demonstration</h2>
<div id="logs" class="logs" aria-label="Demonstration activity logs">Ready. Security events will appear here.</div>
</section>
</main>
<script nonce="${nonce}">
(() => {
  "use strict";
  const content = document.getElementById("content");
  const stepsNode = document.getElementById("steps");
  const logs = document.getElementById("logs");
  const helpMessage = document.getElementById("helpMessage");
  const pauseButton = document.getElementById("pauseButton");
  let csrf = "";
  let serverState = {};
  let rememberedLinkToken = new URLSearchParams(location.search).get("token") || "";
  let screen = "start";
  const steps = [
    ["start","1. Start"],
    ["verify","2. Check recovery code"],
    ["password","3. Create password"],
    ["mfa","4. Confirm security code"],
    ["privacy","5. Accept privacy conditions"],
    ["confirmation","6. Finished"]
  ];

  // Requirements: browser logging is visible here and also sent to browser console.
  function log(message) {
    console.log(message);
    logs.textContent += "\\n" + message;
    logs.scrollTop = logs.scrollHeight;
  }
  function el(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function button(text, className) {
    const node = el("button", text);
    node.type = "button";
    if (className) node.className = className;
    return node;
  }
  function notice(text, kind) {
    const node = el("div", text);
    node.className = "notice " + (kind || "");
    return node;
  }
  function formField(form, labelText, type, name, autocomplete) {
    const label = el("label", labelText);
    const input = document.createElement("input");
    input.type = type; input.name = name; input.required = true;
    input.autocomplete = autocomplete || "off";
    label.htmlFor = name; input.id = name;
    form.append(label, input);
    return input;
  }
  function showMessage(message, kind) {
    const current = content.querySelector(".response-message");
    if (current) current.remove();
    const node = notice(message, kind);
    node.classList.add("response-message");
    content.append(node);
  }
  function setSteps() {
    stepsNode.replaceChildren();
    const activeIndex = Math.max(0, steps.findIndex((item) => item[0] === screen));
    steps.forEach((item, index) => {
      const li = el("li", item[1]);
      if (index === activeIndex) li.className = "active";
      if (index < activeIndex) li.className = "done";
      stepsNode.append(li);
    });
  }
  async function api(path, body) {
    try {
      const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type":"application/json","X-CSRF-Token":csrf},
        body: JSON.stringify(body || {})
      });
      const data = await response.json();
      if (!response.ok && !data.message) data.message = "We could not complete that step. Please try again.";
      return data;
    } catch {
      return {ok:false,message:"Connection unavailable. Your progress is still saved; please try again."};
    }
  }
  function savePlace() {
    localStorage.setItem("hospital-recovery-paused", "yes");
    log("Recovery paused locally. No password or code was saved in the browser.");
    showMessage("Paused. When you are ready, use “Resume recovery” below. Your secure server progress remains available.", "warning");
  }
  pauseButton.addEventListener("click", savePlace);
  document.getElementById("helpButton").addEventListener("click", () => {
    helpMessage.hidden = !helpMessage.hidden;
    helpMessage.textContent = "Short reminder: do one step at a time. Use only this HTTPS hospital page, and never share passwords or one-time codes.";
  });

  function addTitle(title, text) {
    content.append(el("h1", title), el("p", text));
  }
  function render() {
    content.replaceChildren();
    setSteps();
    if (screen === "start") renderStart();
    else if (screen === "verify") renderVerify();
    else if (screen === "password") renderPassword();
    else if (screen === "mfa") renderMfa();
    else if (screen === "privacy") renderPrivacy();
    else renderConfirmation();
  }

  // Requirements: low-distraction, one clear action recovery request and generic account response.
  function renderStart() {
    addTitle("Reset your password", "Step 1 of 6. Enter the account email or account ID you use with the hospital.");
    content.append(notice("For privacy, we give the same response whether or not an account can receive a recovery message.", ""));
    const form = document.createElement("form");
    const identifier = formField(form, "Account email or ID", "text", "identifier", "username");
    identifier.maxLength = 120;
    const submit = document.createElement("button");
    submit.type = "submit"; submit.textContent = "Send recovery code";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      const data = await api("/api/recovery", {identifier:identifier.value});
      submit.disabled = false;
      if (!data.ok) return showMessage(data.message, "error");
      log("Mock hospital delivery: recovery code " + data.mockRecoveryCode + ". This demonstration logs the code only in the browser console and activity logs.");
      rememberedLinkToken = data.mockRecoveryCode;
      localStorage.removeItem("hospital-recovery-paused");
      screen = "verify"; render();
      showMessage(data.message, "success");
      const link = button("Open simulated recovery link", "secondary");
      link.addEventListener("click", () => { location.href = data.recoveryLink; });
      content.append(link);
    });
    content.append(form, el("p", "Next: enter the recovery code from the secure delivery message.", "small"));
    const login = button("I know my password — sign in", "secondary");
    login.addEventListener("click", renderLogin);
    content.append(login);
  }

  function renderLogin() {
    content.replaceChildren();
    addTitle("Sign in securely", "Use this only on the hospital HTTPS page. After sign-in, you will confirm a security code.");
    content.append(notice("Anti-phishing reminder: never follow a password request from an email. Type the hospital address yourself.", "warning"));
    const form = document.createElement("form");
    const identifier = formField(form, "Account email or ID", "text", "identifier", "username");
    const password = formField(form, "Password", "password", "password", "current-password");
    const submit = document.createElement("button"); submit.type="submit"; submit.textContent="Sign in";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled=true;
      const data = await api("/api/login", {identifier:identifier.value,password:password.value});
      password.value = ""; submit.disabled=false;
      if (!data.ok) return showMessage(data.message, "error");
      log("Mock hospital MFA code: " + data.mockMfaCode + ". This code is shown only in browser console and activity logs.");
      screen="mfa"; render(); showMessage("Password checked. Next, enter the security code.", "success");
    });
    const reset = button("I need to reset my password", "secondary");
    reset.addEventListener("click", () => { screen="start"; render(); });
    content.append(form, reset);
  }

  function renderVerify() {
    addTitle("Check your recovery code", "Step 2 of 6. Paste or type the code from the secure hospital recovery message.");
    content.append(notice("You may use either the simulated recovery link or this manual code box. Nothing happens until you choose Verify code.", ""));
    const form = document.createElement("form");
    const token = formField(form, "Recovery code", "text", "token", "one-time-code");
    token.maxLength = 120;
    if (rememberedLinkToken) {
      token.value = rememberedLinkToken;
      content.append(notice("A recovery link opened this page. The code was placed here for you, but it has not been checked yet.", "success"));
    }
    const submit = document.createElement("button"); submit.type="submit"; submit.textContent="Verify code";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled=true;
      const data = await api("/api/verify", {token:token.value});
      submit.disabled=false;
      if (!data.ok) return showMessage(data.message, "error");
      rememberedLinkToken = "";
      history.replaceState({}, "", "/");
      screen="password"; render();
      showMessage(data.message, "success");
    });
    const back = button("Back to recovery request", "secondary");
    back.addEventListener("click", () => { screen="start"; render(); });
    content.append(form, back, el("p", "Recovery codes expire after 15 minutes and can only be used once.", "small muted"));
  }

  function renderPassword() {
    addTitle("Create a strong password", "Step 3 of 6. Choose a new password. We will not show or log it.");
    const policy = el("ul"); policy.className="policy";
    ["At least 12 characters", "An uppercase letter and lowercase letter", "A number and a symbol", "No spaces"].forEach(item => policy.append(el("li", item)));
    content.append(el("h2","Password checklist"), policy);
    const form = document.createElement("form");
    const password = formField(form, "New password", "password", "password", "new-password");
    const confirm = formField(form, "Confirm new password", "password", "confirm", "new-password");
    const submit = document.createElement("button"); submit.type="submit"; submit.textContent="Save new password";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled=true;
      const data = await api("/api/password", {password:password.value,confirm:confirm.value});
      password.value=""; confirm.value=""; submit.disabled=false;
      if (!data.ok) return showMessage(data.message, "error");
      log("Mock hospital MFA code: " + data.mockMfaCode + ". This code is shown only in browser console and activity logs.");
      screen="mfa"; render(); showMessage("New password saved securely. Next, confirm your security code.", "success");
    });
    content.append(form);
  }

  function renderMfa() {
    addTitle("Confirm your security code", "Step 4 of 6. This extra check protects your account after a password reset or sign-in.");
    content.append(notice("Enter the one-time code from the secure hospital message. Never share this code with anyone.", "warning"));
    const form = document.createElement("form");
    const code = formField(form, "Security code", "text", "code", "one-time-code");
    code.inputMode="numeric"; code.maxLength=12;
    const submit = document.createElement("button"); submit.type="submit"; submit.textContent="Confirm code";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault(); submit.disabled=true;
      const data = await api("/api/mfa", {code:code.value});
      submit.disabled=false; code.value="";
      if (!data.ok) return showMessage(data.message, "error");
      screen="privacy"; render(); showMessage(data.message, "success");
    });
    content.append(form);
  }

  function renderPrivacy() {
    addTitle("Review updated privacy conditions", "Step 5 of 6. You are signed in. Read this short summary, then choose one clear action.");
    content.append(notice("Your healthcare account information is protected. This page does not display patient identifiers.", "success"));
    const list = el("ul"); list.className="policy";
    ["Hospital authorities may use your account confirmation to arrange your requested appointment.", "Only authorised hospital staff may access necessary health information.", "You can ask the hospital for help with these conditions at any time."].forEach(item=>list.append(el("li",item)));
    content.append(el("h2","Summary"),list);
    const accept = button("Accept updated privacy conditions");
    accept.addEventListener("click", async () => {
      accept.disabled=true;
      const data=await api("/api/privacy/accept",{});
      accept.disabled=false;
      if(!data.ok)return showMessage(data.message,"error");
      screen="confirmation"; render();
    });
    content.append(accept);
  }

  function renderConfirmation() {
    addTitle("You are all set", "Step 6 of 6. The updated privacy conditions have been recorded.");
    content.append(notice("Simulated appointment-booking handoff completed. Hospital staff can now continue with the medication review appointment request.", "success"));
    content.append(el("p","You may safely close this page. No patient details are shown here."));
    const restart=button("Return to secure start","secondary");
    restart.addEventListener("click",()=>{screen="start";render();});
    content.append(restart);
  }

  async function bootstrap() {
    try {
      const response = await fetch("/api/status",{credentials:"same-origin"});
      const data = await response.json();
      csrf=data.csrf || "";
      serverState=data;
      if (data.authenticated && data.privacyAccepted) screen="confirmation";
      else if (data.authenticated) screen="privacy";
      else if (data.pendingMfa) screen="mfa";
      else if (data.recoveryVerified) screen="password";
      else if (rememberedLinkToken) screen="verify";
      else screen="start";
      if(localStorage.getItem("hospital-recovery-paused")==="yes") log("A paused recovery reminder was found. Resume whenever you feel ready.");
      render();
    } catch {
      content.textContent="Secure connection could not be established. Please refresh this hospital page.";
    }
  }
  bootstrap();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: CERT_FILE,
    key: KEY_FILE,
  },
  async fetch(request) {
    const url = new URL(request.url);
    const nonce = randomToken(18);
    const { session, isNew } = sessionFor(request);

    // Requirements: HTTPS-only behavior. Bun TLS listener rejects plaintext before this handler.
    if (url.protocol !== "https:") {
      return new Response("HTTPS is required.", {
        status: 400,
        headers: secureHeaders(nonce, session, isNew),
      });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery-link")) {
      const headers = secureHeaders(nonce, session, isNew);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(appHtml(nonce), { headers });
    }

    if (request.method === "GET" && url.pathname === "/api/status") {
      return json({
        ok: true,
        csrf: session.csrf,
        recoveryVerified: !!session.recoveryVerified,
        pendingMfa: !!session.pendingMfa,
        authenticated: !!session.authenticated,
        privacyAccepted: !!session.privacyAccepted,
      }, nonce, session, isNew);
    }

    if (!url.pathname.startsWith("/api/")) {
      return new Response("Not found.", { status: 404, headers: secureHeaders(nonce, session, isNew) });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed.", { status: 405, headers: secureHeaders(nonce, session, isNew) });
    }

    if (!csrfValid(request, session)) {
      return genericError("Your security check expired. Refresh this page and try again.", nonce, session, isNew, 403);
    }

    const body = await requestBody(request);
    if (!body) return genericError("We could not read that request. Please try again.", nonce, session, isNew);

    if (url.pathname === "/api/recovery") {
      const limit = rateAllowed(`recovery:${session.id}`, 5, 15 * 60 * 1000);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before another request. Your progress is safe.`, nonce, session, isNew, 429);
      }
      if (!validIdentifier(body.identifier)) {
        return genericError("Please enter a valid account email or account ID.", nonce, session, isNew);
      }

      // Requirements: random, hashed-at-rest, expiring, single-use reset token.
      const token = randomToken(32);
      const tokenHash = sha256(token);
      resets.set(tokenHash, {
        tokenHash,
        accountKey: DEMO_ACCOUNT_KEY,
        expiresAt: Date.now() + RESET_LIFETIME,
        used: false,
      });
      console.log("[simulated delivery] Recovery message prepared without exposing account identity.");
      return json({
        ok: true,
        message: "If this account can receive recovery messages, a secure recovery code has been sent.",
        // Testing requirement: mock delivery code returns only to this same TLS browser session.
        mockRecoveryCode: token,
        recoveryLink: `/recovery-link?token=${encodeURIComponent(token)}`,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/verify") {
      const limit = rateAllowed(`verify:${session.id}`, 8, 15 * 60 * 1000);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before trying another code.`, nonce, session, isNew, 429);
      }
      if (!validToken(body.token)) return genericError("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      const tokenHash = sha256(body.token);
      const reset = resets.get(tokenHash);
      if (!reset) return genericError("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      if (reset.used) return genericError("That recovery code has already been used. Request a new one when ready.", nonce, session, isNew);
      if (Date.now() > reset.expiresAt) return genericError("That recovery code has expired. Request a new one when ready.", nonce, session, isNew);

      session.recoveryTokenHash = tokenHash;
      session.recoveryVerified = true;
      return json({ ok: true, message: "Recovery code confirmed. You can now create a new password." }, nonce, session, isNew);
    }

    if (url.pathname === "/api/password") {
      const limit = rateAllowed(`password:${session.id}`, 5, 15 * 60 * 1000);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before another password attempt.`, nonce, session, isNew, 429);
      }
      if (!session.recoveryVerified || !session.recoveryTokenHash) {
        return genericError("Please verify a recovery code before creating a password.", nonce, session, isNew, 403);
      }
      const reset = resets.get(session.recoveryTokenHash);
      if (!reset || reset.used || Date.now() > reset.expiresAt) {
        session.recoveryVerified = false;
        return genericError("Your recovery code is no longer available. Please request a new code.", nonce, session, isNew, 403);
      }
      const policyFailure = passwordPolicy(body.password);
      if (policyFailure) return genericError(policyFailure, nonce, session, isNew);
      if (body.password !== body.confirm) return genericError("The two passwords do not match. Please try again.", nonce, session, isNew);

      accountPasswordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 10 });
      reset.used = true;
      session.recoveryVerified = false;
      session.recoveryTokenHash = undefined;
      session.pendingMfa = true;
      console.log("[simulated MFA] Code created for password reset.");
      return json({
        ok: true,
        message: "Your new password was saved securely. Confirm the security code to continue.",
        mockMfaCode: MFA_CODE,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/login") {
      const limit = rateAllowed(`login:${session.id}`, 5, 15 * 60 * 1000);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before another sign-in attempt.`, nonce, session, isNew, 429);
      }
      if (!validIdentifier(body.identifier) || typeof body.password !== "string" || body.password.length > 128) {
        return genericError("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);
      }
      const matched = await Bun.password.verify(body.password, accountPasswordHash);
      if (!matched) return genericError("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);

      session.pendingMfa = true;
      session.authenticated = false;
      console.log("[simulated MFA] Code created for sign-in.");
      return json({
        ok: true,
        message: "Password checked. Please confirm your security code.",
        mockMfaCode: MFA_CODE,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/mfa") {
      const limit = rateAllowed(`mfa:${session.id}`, 6, 15 * 60 * 1000);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before another code attempt.`, nonce, session, isNew, 429);
      }
      if (!session.pendingMfa) return genericError("Please sign in or reset your password before confirming a security code.", nonce, session, isNew, 403);
      if (typeof body.code !== "string" || body.code !== MFA_CODE) {
        return genericError("That security code is not correct. Please check the secure message and try again.", nonce, session, isNew, 401);
      }
      session.pendingMfa = false;
      session.authenticated = true;
      return json({ ok: true, message: "Security code confirmed. You are signed in." }, nonce, session, isNew);
    }

    // Requirements: authorization is derived only from this current authenticated session.
    if (url.pathname === "/api/privacy/accept") {
      if (!session.authenticated) {
        return genericError("Please sign in securely before accepting privacy conditions.", nonce, session, isNew, 403);
      }
      session.privacyAccepted = true;
      console.log("[simulated appointment handoff] Privacy conditions accepted for current authorised session.");
      return json({
        ok: true,
        message: "Privacy conditions accepted. The simulated appointment-booking handoff is ready.",
      }, nonce, session, isNew);
    }

    // Requirements: no outbound URL handling, redirects, SSRF targets, or IDOR resource routes exist.
    return genericError("This secure action is not available.", nonce, session, isNew, 404);
  },
  error() {
    // Requirements: production-safe generic server error, with no stack trace or debug exposure.
    return new Response("Secure service unavailable.", { status: 503, headers: { "Cache-Control": "no-store" } });
  },
});

console.log(`Hospital recovery server running securely at https://localhost:${server.port}`);
