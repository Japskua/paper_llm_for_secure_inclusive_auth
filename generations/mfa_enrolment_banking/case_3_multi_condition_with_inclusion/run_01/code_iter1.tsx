
/*
  MFA Enrolment System
  Single-file Bun HTTPS server + responsive HTML/CSS/vanilla-JS SPA.
  Run with: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const cspNonce = randomToken(18);
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
};

type Account = {
  id: string;
  email: string;
  mfaEnabled: boolean;
  encryptedSecret?: { iv: string; ciphertext: string };
  otp?: { codeHash: string; expiresAt: number; used: boolean };
  failedAttempts: number;
  lockedUntil: number;
  backupCodeHashes: string[];
};

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function sha256(value: string): string {
  return Bun.CryptoHasher.hash("sha256", value, "hex");
}

function randomDigits(length = 6): string {
  const values = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(values, (v) => String(v % 10)).join("");
}

function generateSecret(): string {
  // Human-readable Base32 secret for the simulated authenticator manual path.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

function generateBackupCodes(): string[] {
  const bytes = crypto.getRandomValues(new Uint8Array(8 * 10));
  const codes: string[] = [];
  for (let i = 0; i < 10; i++) {
    const part = bytes.slice(i * 8, i * 8 + 8);
    const text = Buffer.from(part).toString("base64url").slice(0, 10).toUpperCase();
    codes.push(`${text.slice(0, 5)}-${text.slice(5, 10)}`);
  }
  return codes;
}

async function encryptSecret(secret: string): Promise<{ iv: string; ciphertext: string }> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(ciphertext).toString("base64url"),
  };
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

function cookieHeader(sessionId: string): string {
  return `mfa_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function securityHeaders(request: Request): Headers {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${cspNonce}'; style-src 'nonce-${cspNonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });

  // Security requirement: CORS is only echoed for this same trusted HTTPS origin.
  const origin = request.headers.get("origin");
  const url = new URL(request.url);
  if (origin === url.origin && isTrustedHost(url.hostname)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function isTrustedHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

function json(request: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(body), { status, headers });
}

function genericUnauthorized(request: Request): Response {
  return json(request, { ok: false, message: "Please sign in again to continue." }, 401);
}

function originIsSafe(request: Request): boolean {
  const origin = request.headers.get("origin");
  const url = new URL(request.url);
  return origin === url.origin && url.protocol === "https:" && isTrustedHost(url.hostname);
}

function getSession(request: Request): { id: string; session: Session; account: Account } | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;

  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }

  // Requirement 1: account ownership is derived only from the authenticated session.
  const account = accounts.get(session.userId);
  if (!account) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return { id, session, account };
}

function requireSession(request: Request): { id: string; session: Session; account: Account } | Response {
  const auth = getSession(request);
  return auth || genericUnauthorized(request);
}

function csrfValid(request: Request, session: Session): boolean {
  return originIsSafe(request) && request.headers.get("x-csrf-token") === session.csrf;
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): boolean {
  return value === undefined || value === "" ||
    (typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value));
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(value);
}

function createSession(userId: string): { id: string; session: Session } {
  const id = randomToken(32);
  const session = { userId, csrf: randomToken(24), createdAt: Date.now(), lastSeenAt: Date.now() };
  sessions.set(id, session);
  return { id, session };
}

async function provision(request: Request, account: Account): Promise<Response> {
  const secret = generateSecret();
  const mockOtp = "246810"; // deterministic mock OTP for evaluation
  account.encryptedSecret = await encryptSecret(secret);
  account.otp = { codeHash: sha256(mockOtp), expiresAt: Date.now() + OTP_LIFETIME_MS, used: false };
  account.failedAttempts = 0;
  account.lockedUntil = 0;

  // Do not log secrets server-side. The browser receives test-only simulated data.
  console.log("Authenticator provisioning issued for authenticated account.");
  return json(request, {
    ok: true,
    secret,
    mockOtp,
    message: "Authenticator setup is ready. Add the secret, then enter the six-digit code.",
  });
}

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Northstar Bank · Security setup</title>
  <style nonce="${cspNonce}">
    :root { color-scheme: light; --ink:#172331; --muted:#536271; --blue:#1259b5; --blue-dark:#083d82; --soft:#edf5ff; --line:#cbd8e6; --good:#156d43; --bad:#a12c2c; --card:#fff; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f3f7fb; color:var(--ink); font-family:Verdana, Arial, sans-serif; font-size:16px; line-height:1.65; letter-spacing:.025em; }
    main { width:min(100%, 620px); min-height:100vh; margin:auto; padding:18px 16px 38px; }
    header { display:flex; gap:11px; align-items:center; margin:4px 0 18px; }
    .mark { width:40px; height:40px; display:grid; place-items:center; background:var(--blue); color:white; border-radius:12px; font-size:22px; }
    h1,h2,h3 { line-height:1.3; letter-spacing:.01em; margin:0 0 12px; }
    h1 { font-size:1.38rem; } h2 { font-size:1.35rem; } h3 { font-size:1rem; }
    .sub { margin:0; color:var(--muted); font-size:.92rem; }
    .steps { display:flex; align-items:center; margin:18px 0; gap:5px; }
    .step { flex:1; text-align:center; padding:6px 2px; border-bottom:4px solid var(--line); color:#607080; font-size:.72rem; }
    .step.active { color:var(--blue-dark); font-weight:700; border-color:var(--blue); }
    .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:22px 18px; box-shadow:0 2px 7px #193c5c0b; }
    p { margin:0 0 15px; } .lead { font-size:1.05rem; }
    label { display:block; margin:16px 0 6px; font-weight:700; }
    input { width:100%; min-height:52px; border:2px solid #9eafc0; border-radius:10px; padding:11px 13px; font:inherit; letter-spacing:.04em; background:white; color:var(--ink); }
    input:focus, button:focus, summary:focus { outline:3px solid #e3a927; outline-offset:2px; }
    .example { color:var(--muted); font-size:.83rem; margin-top:5px; }
    button { width:100%; min-height:53px; border:0; border-radius:10px; padding:11px 15px; cursor:pointer; font:700 1rem/1.35 Verdana,Arial,sans-serif; letter-spacing:.02em; }
    button.primary { background:var(--blue); color:white; margin-top:22px; } button.primary:hover { background:var(--blue-dark); }
    button.secondary { background:white; color:var(--blue-dark); border:2px solid var(--blue); margin-top:11px; }
    button.small { width:auto; min-height:42px; font-size:.88rem; padding:7px 12px; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    .notice { padding:12px 13px; border-radius:10px; margin:15px 0; font-weight:700; }
    .notice.good { color:#0e5533; background:#e5f6eb; border-left:5px solid var(--good); }
    .notice.bad { color:#782222; background:#fff0f0; border-left:5px solid var(--bad); }
    .notice.info { color:#164a84; background:var(--soft); border-left:5px solid var(--blue); }
    .secret { overflow-wrap:anywhere; padding:12px; background:#f4f8fc; border:1px solid var(--line); border-radius:9px; font-family:ui-monospace,Consolas,monospace; letter-spacing:.09em; line-height:1.8; }
    .row { display:flex; flex-wrap:wrap; gap:9px; margin-top:10px; } .row button { flex:1; min-width:130px; }
    canvas { display:block; width:190px; height:190px; image-rendering:pixelated; border:9px solid white; box-shadow:0 0 0 1px var(--line); margin:16px auto; }
    details { margin-top:17px; border-top:1px solid var(--line); padding-top:12px; } summary { cursor:pointer; color:var(--blue-dark); font-weight:700; }
    .codes { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin:14px 0; }
    .code { padding:9px 6px; background:#f4f8fc; border-radius:7px; text-align:center; font-family:ui-monospace,Consolas,monospace; font-weight:700; letter-spacing:.04em; }
    .logs { margin-top:22px; background:#14202b; color:#dbeefc; border-radius:12px; padding:13px; }
    .logs h2 { font-size:1rem; } #logList { margin:0; padding-left:19px; font: .77rem/1.55 ui-monospace,Consolas,monospace; max-height:160px; overflow:auto; }
    .footer { text-align:center; margin-top:18px; color:var(--muted); font-size:.82rem; }
    .logout { background:none; border:0; color:var(--blue-dark); text-decoration:underline; min-height:30px; padding:4px; width:auto; font:inherit; cursor:pointer; }
    @media (max-width:390px) { main { padding:12px 11px 28px; } .card { padding:18px 14px; } .step { font-size:.65rem; } .codes { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header>
  <nav class="steps" aria-label="Setup progress">
    <div class="step" id="s1">1. Confirm</div><div class="step" id="s2">2. App</div><div class="step" id="s3">3. Check</div><div class="step" id="s4">4. Save</div>
  </nav>
  <section id="app" class="card" aria-live="polite">Loading secure setup…</section>
  <section class="logs" aria-label="Logs"><h2>Logs</h2><ul id="logList"><li>Secure setup page ready.</li></ul></section>
  <footer class="footer">Take your time. There is no reading timer.</footer>
</main>

<script nonce="${cspNonce}">
/* Requirement: client-side SPA uses only in-memory variables, never localStorage/sessionStorage. */
const app = document.getElementById("app");
const logList = document.getElementById("logList");
let csrf = "";
let setupSecret = "";
let visibleSecret = true;
let currentCodes = [];

function log(message) {
  console.log(message);
  const item = document.createElement("li");
  item.textContent = message;
  logList.appendChild(item);
  logList.scrollTop = logList.scrollHeight;
}
function setSteps(number) {
  document.querySelectorAll(".step").forEach((el, i) => el.classList.toggle("active", i + 1 === number));
}
function esc(value) {
  const node = document.createElement("span"); node.textContent = String(value); return node.innerHTML;
}
async function api(path, body) {
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type":"application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body || {})
  });
  const data = await response.json().catch(() => ({ ok:false, message:"Something went wrong. Please try again." }));
  if (response.status === 401) { csrf = ""; showSignIn("Your secure session ended. Please sign in again."); }
  return { response, data };
}
function notice(message, type) { return '<div class="notice ' + type + '">' + esc(message) + "</div>"; }
function help() { return '<details><summary>Help with this step</summary><p>If you need a pause, leave this page open. Your choices stay clear and you can retry safely.</p></details>'; }

function showSignIn(message = "") {
  setSteps(1);
  app.innerHTML = '<h2>Confirm your account</h2><p class="lead">Use the email you used when opening your account.</p>' +
    (message ? notice(message, "info") : "") +
    '<label for="email">Email address</label><input id="email" type="email" autocomplete="email" inputmode="email" placeholder="marcus@example.com">' +
    '<p class="example">Example: marcus@example.com</p>' +
    '<label for="phone">Phone number <span class="sub">(optional)</span></label><input id="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+44 7700 900123">' +
    '<p class="example">Example: +44 7700 900123</p><button class="primary" id="signin">Continue</button>' + help();
  document.getElementById("signin").onclick = signIn;
}
async function signIn() {
  const email = document.getElementById("email").value;
  const phone = document.getElementById("phone").value;
  const button = document.getElementById("signin"); button.disabled = true;
  const response = await fetch("/api/signin", { method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email, phone}) });
  const data = await response.json().catch(() => ({ok:false,message:"Please check your details and try again."}));
  if (!response.ok || !data.ok) { button.disabled = false; app.insertAdjacentHTML("afterbegin", notice(data.message || "Please check your details and try again.", "bad")); return; }
  csrf = data.csrf;
  log("Identity confirmed. Starting authenticator setup.");
  showSetup();
}
function showSetup(message = "") {
  setSteps(2);
  app.innerHTML = '<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app on this phone. You can scan the setup image or use the short secret below.</p>' +
    (message ? notice(message, "good") : "") +
    '<button class="primary" id="getSetup">Show secure setup</button>' + help();
  document.getElementById("getSetup").onclick = getSetup;
}
async function getSetup() {
  const button = document.getElementById("getSetup"); button.disabled = true;
  const {response, data} = await api("/api/provision", {});
  if (!response.ok || !data.ok) { button.disabled = false; app.insertAdjacentHTML("afterbegin", notice(data.message || "We could not prepare setup. Try again.", "bad")); return; }
  setupSecret = data.secret;
  // Testing-only simulated delivery logs required by the task. No server logs contain secrets.
  console.log("[TEST ONLY] Authenticator secret:", data.secret);
  console.log("[TEST ONLY] Mock authenticator code:", data.mockOtp);
  log("Mock authenticator setup delivered to this screen. A test code is ready.");
  showProvisioning(data.message);
}
function drawSetupImage(secret) {
  const canvas = document.getElementById("setupQR"); if (!canvas) return;
  const ctx = canvas.getContext("2d"), size = 29, cell = 7;
  canvas.width = size * cell; canvas.height = size * cell;
  const hash = secret.split("").reduce((n,c) => ((n * 31) + c.charCodeAt(0)) >>> 0, 7);
  ctx.fillStyle = "#fff"; ctx.fillRect(0,0,canvas.width,canvas.height);
  function finder(x,y) { ctx.fillStyle="#102438"; ctx.fillRect(x*cell,y*cell,7*cell,7*cell); ctx.fillStyle="#fff";ctx.fillRect((x+1)*cell,(y+1)*cell,5*cell,5*cell);ctx.fillStyle="#102438";ctx.fillRect((x+2)*cell,(y+2)*cell,3*cell,3*cell); }
  finder(1,1); finder(21,1); finder(1,21);
  for(let y=0;y<size;y++) for(let x=0;x<size;x++) {
    if ((x<9&&y<9)||(x>19&&y<9)||(x<9&&y>19)) continue;
    const bit = ((hash ^ ((x+3)*1103515245) ^ ((y+9)*12345)) >>> ((x+y)%19)) & 1;
    if(bit) { ctx.fillStyle="#102438"; ctx.fillRect(x*cell,y*cell,cell,cell); }
  }
}
function showProvisioning(message) {
  setSteps(2);
  app.innerHTML = '<h2>Your setup image is ready</h2>' + notice(message, "good") +
    '<p>Scan this simulated setup image in your authenticator app. If scanning is difficult, use the secret instead.</p>' +
    '<canvas id="setupQR" role="img" aria-label="Simulated authenticator QR setup image"></canvas>' +
    '<h3>Manual secret</h3><div class="secret" id="secretText">' + esc(setupSecret) + '</div>' +
    '<div class="row"><button class="secondary small" id="copySecret">Copy secret</button><button class="secondary small" id="hideSecret">Hide secret</button></div>' +
    '<button class="primary" id="goVerify">I added it to my app</button><button class="secondary" id="newSetup">Request a new setup</button>' + help();
  drawSetupImage(setupSecret);
  document.getElementById("copySecret").onclick = () => copyText(setupSecret, "Secret copied. Paste it into your authenticator app.");
  document.getElementById("hideSecret").onclick = toggleSecret;
  document.getElementById("goVerify").onclick = showVerify;
  document.getElementById("newSetup").onclick = getSetup;
}
function toggleSecret() {
  visibleSecret = !visibleSecret;
  document.getElementById("secretText").textContent = visibleSecret ? setupSecret : "Secret hidden";
  document.getElementById("hideSecret").textContent = visibleSecret ? "Hide secret" : "Show secret";
}
async function copyText(text, message) {
  try { await navigator.clipboard.writeText(text); log(message); }
  catch { log("Copy was not available. You can select the text shown above."); }
}
function showVerify(message = "") {
  setSteps(3);
  app.innerHTML = '<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>' +
    (message ? notice(message, "info") : "") +
    '<label for="otp">Six-digit code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810">' +
    '<p class="example">Example: 246810. You have plenty of time to enter it.</p><button class="primary" id="verify">Verify code</button><button class="secondary" id="backSetup">Go back to setup</button>' + help();
  document.getElementById("verify").onclick = verifyOtp;
  document.getElementById("backSetup").onclick = () => showProvisioning("You can view the setup details again.");
}
async function verifyOtp() {
  const otp = document.getElementById("otp").value.trim();
  const button = document.getElementById("verify"); button.disabled = true;
  const {response, data} = await api("/api/verify-otp", {otp});
  if (!response.ok || !data.ok) {
    button.disabled = false;
    app.insertAdjacentHTML("afterbegin", notice(data.message || "That code could not be checked. Try again.", "bad"));
    return;
  }
  currentCodes = data.codes;
  console.log("[TEST ONLY] Backup recovery codes:", data.codes);
  log("Authenticator verified. Recovery codes are ready to save.");
  showCodes("Your authenticator is now connected.");
}
function showCodes(message) {
  setSteps(4);
  const codes = currentCodes.map(code => '<div class="code">' + esc(code) + "</div>").join("");
  app.innerHTML = '<h2>Save your recovery codes</h2>' + notice(message, "good") +
    '<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p>' +
    '<div class="codes" id="codes">' + codes + '</div><button class="primary" id="copyCodes">Copy all recovery codes</button>' +
    '<button class="secondary" id="finish">I saved my codes</button>' + help();
  document.getElementById("copyCodes").onclick = () => copyText(currentCodes.join("\\n"), "Recovery codes copied. Keep them private.");
  document.getElementById("finish").onclick = showComplete;
}
function showComplete() {
  setSteps(4);
  currentCodes = [];
  setupSecret = "";
  app.innerHTML = '<h2>Setup complete ✓</h2>' + notice("Multi-factor authentication is on for your account.", "good") +
    '<p class="lead">You will use your authenticator when a payment needs extra protection.</p>' +
    '<button class="primary" id="regenerate">Generate new recovery codes</button><button class="secondary" id="logout">Sign out</button>' + help();
  document.getElementById("regenerate").onclick = regenerate;
  document.getElementById("logout").onclick = logout;
}
async function regenerate() {
  const {response, data} = await api("/api/regenerate-backup-codes", {});
  if (!response.ok || !data.ok) { app.insertAdjacentHTML("afterbegin", notice(data.message || "New codes could not be made. Try again.", "bad")); return; }
  currentCodes = data.codes;
  console.log("[TEST ONLY] New backup recovery codes:", data.codes);
  log("New recovery codes were generated. The old codes no longer work.");
  showCodes("New recovery codes have replaced the old ones.");
}
async function logout() {
  await api("/api/logout", {});
  csrf = ""; setupSecret = ""; currentCodes = [];
  log("You signed out. This device no longer has an active session.");
  showSignIn("You have signed out safely.");
}
showSignIn();
</script>
</body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);

  // Requirement 2: HTTPS-only operation. Bun's TLS listener handles all traffic.
  if (url.protocol !== "https:" || !isTrustedHost(url.hostname)) {
    return new Response("Not found", { status: 404, headers: securityHeaders(request) });
  }

  if (request.method === "OPTIONS") {
    if (!originIsSafe(request)) return new Response(null, { status: 403, headers: securityHeaders(request) });
    const headers = securityHeaders(request);
    headers.set("Access-Control-Allow-Methods", "POST");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }

  if (request.method === "GET" && url.pathname === "/") {
    const headers = securityHeaders(request);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(pageHtml(), { headers });
  }

  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!originIsSafe(request)) return json(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const body = await readJson(request);
    if (!body || !validEmail(body.email) || !validPhone(body.phone)) {
      return json(request, { ok: false, message: "Enter an email like marcus@example.com and check the phone number format." }, 400);
    }

    // Mock account selection never accepts a user/account identifier from the browser.
    const accountId = "authenticated-demo-account";
    let account = accounts.get(accountId);
    if (!account) {
      account = { id: accountId, email: body.email.toLowerCase(), mfaEnabled: false, failedAttempts: 0, lockedUntil: 0, backupCodeHashes: [] };
      accounts.set(accountId, account);
    } else {
      account.email = body.email.toLowerCase();
    }

    // Requirement 5: a brand-new random session ID is created on authentication.
    const created = createSession(accountId);
    console.log("Secure authenticated session created.");
    return json(request, { ok: true, csrf: created.session.csrf }, 200, { "Set-Cookie": cookieHeader(created.id) });
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    const auth = requireSession(request);
    if (auth instanceof Response) return auth;
    if (!csrfValid(request, auth.session)) return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(auth.id);
    return json(request, { ok: true }, 200, { "Set-Cookie": expiredCookie() });
  }

  const auth = requireSession(request);
  if (auth instanceof Response) return auth;
  if (request.method !== "POST" || !csrfValid(request, auth.session)) {
    return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  }

  if (url.pathname === "/api/provision") {
    return provision(request, auth.account);
  }

  if (url.pathname === "/api/verify-otp") {
    const body = await readJson(request);
    if (!body || !validOtp(body.otp)) {
      return json(request, { ok: false, message: "Enter exactly six numbers, for example 246810." }, 400);
    }
    const account = auth.account;
    const now = Date.now();
    if (account.lockedUntil > now) {
      return json(request, { ok: false, message: "Too many incorrect codes were entered. Please wait a few minutes, then try again." }, 429);
    }
    if (!account.otp || account.otp.expiresAt < now) {
      return json(request, { ok: false, message: "This setup code is no longer available. Request a new setup and try again." }, 400);
    }
    if (account.otp.used) {
      return json(request, { ok: false, message: "That code was already used. Request a new setup code and try again." }, 400);
    }
    if (sha256(body.otp) !== account.otp.codeHash) {
      account.failedAttempts++;
      if (account.failedAttempts >= MAX_FAILURES) account.lockedUntil = now + LOCKOUT_MS;
      const suffix = account.failedAttempts >= MAX_FAILURES ? " Please wait a few minutes before trying again." : " Check your authenticator app and enter its current six-digit code.";
      return json(request, { ok: false, message: "That code did not match." + suffix }, 400);
    }

    account.otp.used = true;
    account.mfaEnabled = true;
    account.failedAttempts = 0;
    const codes = generateBackupCodes();
    account.backupCodeHashes = codes.map(sha256);
    console.log("MFA enabled for authenticated account.");
    return json(request, { ok: true, codes }, 200);
  }

  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!auth.account.mfaEnabled) return json(request, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const codes = generateBackupCodes();
    auth.account.backupCodeHashes = codes.map(sha256);
    console.log("Recovery codes regenerated for authenticated account.");
    return json(request, { ok: true, codes });
  }

  if (url.pathname === "/api/recovery/verify") {
    const body = await readJson(request);
    if (!body || !validRecoveryCode(body.code)) {
      return json(request, { ok: false, message: "Enter a recovery code in the format ABCDE-12345." }, 400);
    }
    const hash = sha256(body.code.toUpperCase());
    const index = auth.account.backupCodeHashes.indexOf(hash);
    if (index < 0) return json(request, { ok: false, message: "That recovery code could not be used. Check the code and try again." }, 400);
    auth.account.backupCodeHashes.splice(index, 1);
    return json(request, { ok: true, message: "Recovery code accepted." });
  }

  return new Response("Not found", { status: 404, headers: securityHeaders(request) });
}

const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");

Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  hostname: "localhost",
  tls: { cert: certFile, key: keyFile },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      // Requirement 2: no debug traces or sensitive error output.
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: securityHeaders(request),
      });
    }
  },
});

console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
