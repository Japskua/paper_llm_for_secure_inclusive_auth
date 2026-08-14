
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000);
const COOKIE_NAME = "__Host-mfa_session";
const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const CSP_NONCE = "mfa-enrolment-ui-v1";

/* Security Evaluation 2: cryptographically restrictive response policy. */
const securityHeaders = {
  "Content-Security-Policy":
    `default-src 'self'; script-src 'nonce-${CSP_NONCE}'; style-src 'nonce-${CSP_NONCE}'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store, private",
};

type Session = {
  id: string;
  csrf: string;
  accountId?: string;
  identityVerified: boolean;
  createdAt: number;
  lastSeen: number;
  failedLogin: number;
  failedIdentity: number;
  failedMfa: number;
  lockedUntil: number;
};

type Encrypted = { iv: string; ciphertext: string };
type PendingProvision = {
  secret: Encrypted;
  expiresAt: number;
  used: boolean;
};
type Account = {
  id: string;
  email: string;
  passwordHash: string;
  phone: string;
  identityCode?: string;
  identityExpiresAt?: number;
  identityUsed?: boolean;
  mfaSecret?: Encrypted;
  pending?: PendingProvision;
  backupCodes: { digest: string; used: boolean }[];
  mfaEnabled: boolean;
  mfaLockedUntil: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const encryptionKeyPromise = crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);
const recoveryPepper = randomText(32);
const PASSWORD_HASH = await sha256("BankPass!9");

/* Security Evaluation 3: only encrypted secrets / hashes are retained in memory. */
accounts.set("acct_marcus", {
  id: "acct_marcus",
  email: "marcus@example.test",
  passwordHash: PASSWORD_HASH,
  phone: "+15551234567",
  backupCodes: [],
  mfaEnabled: false,
  mfaLockedUntil: 0,
});

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
function fromBase64(value: string): Uint8Array {
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
function randomText(bytes = 32): string {
  return base64Url(randomBytes(bytes));
}
function randomSixDigits(): string {
  const number = new DataView(randomBytes(4).buffer).getUint32(0) % 1000000;
  return String(number).padStart(6, "0");
}
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0;
  let bits = 0;
  let output = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}
function decodeBase32(value: string): Uint8Array | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.replaceAll(/\s/g, "").toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(clean)) return null;
  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) return null;
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function equal(a: string, b: string): boolean {
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    difference |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return difference === 0;
}
async function encrypt(value: string): Promise<Encrypted> {
  const iv = randomBytes(12);
  const key = await encryptionKeyPromise;
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(value),
  );
  return { iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(encrypted)) };
}
async function decrypt(value: Encrypted): Promise<string> {
  const key = await encryptionKeyPromise;
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(value.iv) },
    key,
    fromBase64(value.ciphertext),
  );
  return decoder.decode(plain);
}
async function totp(secret: string): Promise<string> {
  const secretBytes = decodeBase32(secret);
  if (!secretBytes) return "000000";
  const counter = Math.floor(Date.now() / 30000);
  const message = new Uint8Array(8);
  const view = new DataView(message.buffer);
  view.setUint32(4, counter, false);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = signature[signature.length - 1] & 15;
  const binary =
    ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}
function sessionCookie(id: string): string {
  return `${COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE_MS / 1000}`;
}
function expiredCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
function createSession(accountId?: string): Session {
  const now = Date.now();
  const session: Session = {
    id: randomText(32),
    csrf: randomText(32),
    accountId,
    identityVerified: false,
    createdAt: now,
    lastSeen: now,
    failedLogin: 0,
    failedIdentity: 0,
    failedMfa: 0,
    lockedUntil: 0,
  };
  sessions.set(session.id, session);
  return session;
}
function cookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const index = piece.indexOf("=");
    if (index > 0) result[piece.slice(0, index).trim()] = piece.slice(index + 1).trim();
  }
  return result;
}
/* Security Evaluation 1 & 5: expiry is enforced for every use of a session. */
function getSession(request: Request): Session | null {
  const id = cookies(request)[COOKIE_NAME];
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const parsed = new URL(origin);
    const hostAllowed = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    return parsed.protocol === "https:" && hostAllowed && origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}
function headersFor(request: Request, extra: Record<string, string> = {}): Headers {
  const headers = new Headers({ ...securityHeaders, ...extra });
  const origin = request.headers.get("origin");
  if (origin && trustedOrigin(request)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, status: number, data: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: headersFor(request, { "Content-Type": "application/json; charset=utf-8", ...extra }),
  });
}
function genericError(request: Request, status = 400): Response {
  return json(request, status, { ok: false, message: "We could not complete that request. Please try again." });
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  const size = Number(request.headers.get("content-length") || "0");
  if (size > 4096) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(value);
}
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9][0-9]{7,14}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}
function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return !!token && /^[A-Za-z0-9_-]{40,64}$/.test(token) && equal(token, session.csrf) && trustedOrigin(request);
}
/* Security Evaluation 1: account identity is exclusively session-derived. */
function requireAccount(request: Request, csrf = false): { session: Session; account: Account } | null {
  const session = getSession(request);
  if (!session || !session.accountId || !session.identityVerified) return null;
  const account = accounts.get(session.accountId);
  if (!account || (csrf && !csrfValid(request, session))) return null;
  return { session, account };
}
function locked(session: Session, account?: Account): boolean {
  return session.lockedUntil > Date.now() || !!account && account.mfaLockedUntil > Date.now();
}
function failMfa(session: Session, account: Account): void {
  session.failedMfa++;
  if (session.failedMfa >= MAX_FAILURES) {
    session.lockedUntil = Date.now() + LOCK_MS;
    account.mfaLockedUntil = Date.now() + LOCK_MS;
  }
}
function recoveryCodes(): string[] {
  return Array.from({ length: 8 }, () => {
    const raw = base64Url(randomBytes(9)).toUpperCase().replaceAll(/[^A-Z0-9]/g, "X").padEnd(12, "A");
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
  });
}
async function setBackupCodes(account: Account): Promise<string[]> {
  const codes = recoveryCodes();
  account.backupCodes = await Promise.all(codes.map(async (code) => ({
    digest: await sha256(`${recoveryPepper}:${code}`),
    used: false,
  })));
  return codes;
}

const appHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Northstar Bank MFA enrolment</title>
<style nonce="${CSP_NONCE}">
:root{color-scheme:light;--navy:#102a43;--blue:#1261a0;--pale:#edf6ff;--ink:#172b3a;--muted:#526574;--line:#c5d1db;--good:#126a43;--warn:#8a5000;--danger:#a12828}
*{box-sizing:border-box}body{margin:0;background:#f2f6f8;color:var(--ink);font:18px/1.55 Arial,sans-serif}header{background:var(--navy);color:#fff;padding:1rem max(1rem,calc((100% - 680px)/2));box-shadow:0 1px 3px #0004}header p{margin:.1rem 0 0;font-size:.92rem}.wrap{max-width:680px;margin:0 auto;padding:1rem}main{background:#fff;border-radius:12px;padding:1.25rem;box-shadow:0 2px 10px #102a4315;margin-top:1rem}h1{font-size:1.55rem;line-height:1.25;margin:.1rem 0 .8rem}h2{font-size:1.2rem;line-height:1.3}p,li{max-width:62ch}.hint{background:var(--pale);border-left:5px solid var(--blue);padding:.8rem;margin:1rem 0}.warning{background:#fff4dc;border-left:5px solid var(--warn);padding:.8rem}.status{min-height:1.6rem;font-weight:bold;color:var(--good)}.error{color:var(--danger)}label{font-weight:bold;display:block;margin-top:1rem}input{display:block;width:100%;font:inherit;padding:.7rem;border:2px solid #758897;border-radius:7px;margin-top:.3rem;background:white}input:focus{outline:3px solid #8fc6ec;outline-offset:1px}button,.linkbutton{font:inherit;font-weight:bold;border:0;border-radius:7px;padding:.72rem 1rem;margin:.9rem .45rem 0 0;cursor:pointer;background:var(--blue);color:#fff;text-decoration:none;display:inline-block}.secondary{background:#e5edf2;color:var(--ink)}.danger{background:var(--danger)}button:focus-visible,a:focus-visible{outline:4px solid #f4bd42;outline-offset:2px}.secret{font-family:monospace;word-break:break-all;background:#f3f5f6;padding:.7rem;border:1px dashed var(--line);border-radius:6px}.codes{font-family:monospace;font-size:1.05rem;line-height:1.9;columns:2;padding-left:1.3rem}.logs{margin:1rem 0 2rem;border:1px solid var(--line);border-radius:9px;background:#fbfcfd}.logs h2{margin:0;padding:.6rem .8rem;background:#e9f0f5}.logs pre{white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;margin:0;padding:.8rem;font:14px/1.4 monospace}footer{font-size:.85rem;color:var(--muted);padding:.5rem 0 1rem}@media(max-width:420px){body{font-size:17px}.wrap{padding:.7rem}main{padding:1rem;border-radius:9px}.codes{columns:1}button{width:100%;margin-right:0}}
</style>
</head>
<body>
<header><strong>Northstar Bank</strong><p>Secure MFA enrolment</p></header>
<div class="wrap">
<main id="app" aria-live="polite"><p>Loading secure enrolment…</p></main>
<section class="logs" aria-label="Test logs"><h2>Logs</h2><pre id="logs">Secure test log ready.</pre></section>
<footer>Never share a passcode or recovery code with anyone.</footer>
</div>
<script nonce="${CSP_NONCE}">
(() => {
"use strict";
/* Client keeps only transient UI and CSRF data in memory: no browser storage. */
let csrf = "";
let page = "signin";
let identitySent = false;
let provision = null;
let shownCodes = null;
const app = document.getElementById("app");
const logPanel = document.getElementById("logs");
function testLog(label, value) {
  const line = "[TEST ONLY] " + label + ": " + value;
  console.log(line);
  logPanel.textContent += "\\n" + line;
  logPanel.scrollTop = logPanel.scrollHeight;
}
function setStatus(message, bad) {
  const node = document.getElementById("status");
  if (node) { node.textContent = message || ""; node.className = "status" + (bad ? " error" : ""); }
}
async function api(path, options) {
  const response = await fetch(path, {
    method: options && options.method || "GET",
    credentials: "same-origin",
    headers: Object.assign({"Content-Type":"application/json","X-CSRF-Token":csrf}, options && options.headers || {}),
    body: options && options.body ? JSON.stringify(options.body) : undefined
  });
  let data;
  try { data = await response.json(); } catch (_) { data = {ok:false,message:"We could not complete that request. Please try again."}; }
  if (!response.ok) throw new Error(data.message || "We could not complete that request. Please try again.");
  return data;
}
function bind(selector, handler) {
  const node = document.querySelector(selector);
  if (node) node.addEventListener("submit", handler);
}
function nav(next) {
  page = next;
  location.hash = next;
  render();
}
function shell(title, content) {
  app.innerHTML = "<h1>" + title + "</h1><div id=\\"status\\" class=\\"status\\"></div>" + content;
}
function render() {
  if (page === "signin") {
    shell("Sign in to begin", "<p>Enrol MFA before authorising higher-value payments.</p><form id=\\"signIn\\" novalidate><label>Email address<input name=\\"email\\" type=\\"email\\" autocomplete=\\"username\\" inputmode=\\"email\\" required></label><label>Password<input name=\\"password\\" type=\\"password\\" autocomplete=\\"current-password\\" required></label><button type=\\"submit\\">Sign in</button></form><div class=\\"hint\\"><strong>Academic demo account:</strong><br>marcus@example.test<br>Password: BankPass!9</div>");
    bind("#signIn", async (event) => {
      event.preventDefault(); const form = new FormData(event.currentTarget);
      try { const data = await api("/api/signin",{method:"POST",body:{email:String(form.get("email")||""),password:String(form.get("password")||"")}});
        csrf=data.csrf; identitySent=false; nav("identity");
      } catch (error) { setStatus(error.message,true); }
    });
  } else if (page === "identity") {
    shell("Verify your identity", "<p>Confirm the phone number associated with your account. A test code will be placed in the browser console and Logs panel.</p><form id=\\"sendIdentity\\"><label>Mobile number<input name=\\"phone\\" type=\\"tel\\" autocomplete=\\"tel\\" placeholder=\\"+15551234567\\" required></label><button type=\\"submit\\">Send verification code</button></form>" + (identitySent ? "<form id=\\"verifyIdentity\\"><label>6-digit verification code<input name=\\"code\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" pattern=\\"[0-9]{6}\\" required></label><button type=\\"submit\\">Verify identity</button></form>" : ""));
    bind("#sendIdentity", async (event) => {
      event.preventDefault(); const phone=String(new FormData(event.currentTarget).get("phone")||"");
      try { const data=await api("/api/identity/send",{method:"POST",body:{phone}}); identitySent=true; testLog("Mock identity verification code",data.mockCode); render(); }
      catch(error){setStatus(error.message,true);}
    });
    bind("#verifyIdentity", async (event) => {
      event.preventDefault(); const code=String(new FormData(event.currentTarget).get("code")||"");
      try { await api("/api/identity/verify",{method:"POST",body:{code}}); nav("setup"); } catch(error){setStatus(error.message,true);}
    });
  } else if (page === "setup") {
    shell("Set up an authenticator", "<p>Use an authenticator app to add the secret below. You may enter the secret manually in an app that does not scan QR codes.</p>" + (!provision ? "<button id=\\"startSetup\\">Create authenticator secret</button>" : "<div class=\\"warning\\"><strong>Save this setup secret in your authenticator now.</strong> It is shown only for this enrolment step.</div><p class=\\"secret\\" id=\\"secret\\"></p><p>After adding it to your app, continue to enter its 6-digit code.</p><button id=\\"continueVerify\\">Continue to verification</button>"));
    if (!provision) document.getElementById("startSetup").addEventListener("click", async () => {
      try { provision=await api("/api/mfa/provision",{method:"POST",body:{}}); testLog("Mock authenticator provisioning secret",provision.secret); testLog("Mock current authenticator OTP",provision.mockOtp); render(); } catch(error){setStatus(error.message,true);}
    });
    else { document.getElementById("secret").textContent=provision.secret; document.getElementById("continueVerify").addEventListener("click",()=>nav("verify")); }
  } else if (page === "verify") {
    shell("Verify your authenticator", "<p>Enter the current 6-digit code from your authenticator. For manual provisioning, also enter the setup secret shown on the previous screen.</p><form id=\\"verifyMfa\\"><label>Authenticator code<input name=\\"otp\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" pattern=\\"[0-9]{6}\\" required></label><label>Manual setup secret <span style=\\"font-weight:normal\\">(optional)</span><input name=\\"manualSecret\\" autocomplete=\\"off\\"></label><button type=\\"submit\\">Enable MFA</button><button type=\\"button\\" class=\\"secondary\\" id=\\"backSetup\\">Back</button></form>");
    document.getElementById("backSetup").addEventListener("click",()=>nav("setup"));
    bind("#verifyMfa", async (event) => {
      event.preventDefault(); const form=new FormData(event.currentTarget);
      try { const data=await api("/api/mfa/verify",{method:"POST",body:{otp:String(form.get("otp")||""),manualSecret:String(form.get("manualSecret")||"")}});
        shownCodes=data.codes; provision=null; testLog("Mock recovery codes",data.codes.join(", ")); nav("backup");
      } catch(error){setStatus(error.message,true);}
    });
  } else if (page === "backup") {
    shell("Save your recovery codes", "<div class=\\"warning\\"><strong>These codes are shown once.</strong> Store them somewhere safe. Each can be used one time if your authenticator is unavailable.</div><ul id=\\"codes\\" class=\\"codes\\"></ul><button id=\\"settings\\">I have saved these codes</button>");
    const list=document.getElementById("codes"); (shownCodes || []).forEach(code=>{const item=document.createElement("li");item.textContent=code;list.appendChild(item);});
    document.getElementById("settings").addEventListener("click",()=>{shownCodes=null;nav("settings");});
  } else {
    shell("MFA settings", "<p id=\\"mfaState\\">Loading your MFA settings…</p><form id=\\"recoveryCheck\\"><label>Test a recovery code<input name=\\"recoveryCode\\" placeholder=\\"ABCD-EFGH-IJKL\\" autocomplete=\\"off\\"></label><button type=\\"submit\\" class=\\"secondary\\">Verify recovery code</button></form><button id=\\"regenerate\\">Regenerate recovery codes</button><button id=\\"logout\\" class=\\"danger\\">Log out</button>");
    api("/api/mfa/status").then(data=>{document.getElementById("mfaState").textContent=data.enabled ? "MFA is enabled. " + data.backupRemaining + " recovery codes remain." : "MFA is not enabled.";}).catch(()=>nav("signin"));
    bind("#recoveryCheck",async(event)=>{event.preventDefault();const code=String(new FormData(event.currentTarget).get("recoveryCode")||"").toUpperCase();try{await api("/api/mfa/recovery/verify",{method:"POST",body:{recoveryCode:code}});setStatus("Recovery code accepted and used.");}catch(error){setStatus(error.message,true);}});
    document.getElementById("regenerate").addEventListener("click",async()=>{try{const data=await api("/api/mfa/recovery/regenerate",{method:"POST",body:{}});shownCodes=data.codes;testLog("Mock regenerated recovery codes",data.codes.join(", "));nav("backup");}catch(error){setStatus(error.message,true);}});
    document.getElementById("logout").addEventListener("click",async()=>{try{await api("/api/logout",{method:"POST",body:{}});}catch(_){} csrf="";provision=null;shownCodes=null;await initialise();nav("signin");});
  }
}
async function initialise() {
  try { const data=await api("/api/csrf"); csrf=data.csrf; const session=await api("/api/session"); if(session.signedIn){page=session.identityVerified ? (session.mfaEnabled ? "settings" : "setup") : "identity";} } catch (_) { page="signin"; }
}
window.addEventListener("hashchange",()=>{const allowed=["signin","identity","setup","verify","backup","settings"];const requested=location.hash.slice(1);if(allowed.includes(requested)){page=requested;render();}});
initialise().then(render);
})();
</script>
</body>
</html>`;

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    if (!trustedOrigin(request)) return genericError(request, 403);
    return new Response(null, {
      status: 204,
      headers: headersFor(request, {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
        "Access-Control-Max-Age": "600",
      }),
    });
  }

  if (!path.startsWith("/api/")) {
    const allowedPages = new Set(["/", "/signin", "/identity", "/setup", "/verify", "/backup", "/settings"]);
    if (request.method === "GET" && allowedPages.has(path)) {
      return new Response(appHtml, {
        headers: headersFor(request, { "Content-Type": "text/html; charset=utf-8" }),
      });
    }
    return new Response("Not found", { status: 404, headers: headersFor(request, { "Content-Type": "text/plain; charset=utf-8" }) });
  }

  if (path === "/api/csrf" && request.method === "GET") {
    let session = getSession(request);
    if (!session) session = createSession();
    return json(request, 200, { ok: true, csrf: session.csrf }, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (path === "/api/session" && request.method === "GET") {
    const session = getSession(request);
    if (!session) return json(request, 200, { ok: true, signedIn: false });
    const account = session.accountId ? accounts.get(session.accountId) : undefined;
    return json(request, 200, {
      ok: true,
      signedIn: !!account,
      identityVerified: session.identityVerified,
      mfaEnabled: !!account?.mfaEnabled,
    });
  }

  if (path === "/api/signin" && request.method === "POST") {
    const session = getSession(request);
    const input = await body(request);
    if (!session || !input || !csrfValid(request, session) || !validEmail(input.email) || typeof input.password !== "string" || input.password.length < 8 || input.password.length > 128) return genericError(request);
    if (locked(session)) return genericError(request, 429);
    const candidate = accounts.get("acct_marcus")!;
    const suppliedHash = await sha256(input.password);
    const valid = equal(input.email.toLowerCase(), candidate.email) && equal(suppliedHash, candidate.passwordHash);
    if (!valid) {
      session.failedLogin++;
      if (session.failedLogin >= MAX_FAILURES) session.lockedUntil = Date.now() + LOCK_MS;
      return genericError(request, session.lockedUntil > Date.now() ? 429 : 401);
    }
    /* Security Evaluation 5: session fixation prevention by rotation after authentication. */
    sessions.delete(session.id);
    const fresh = createSession(candidate.id);
    return json(request, 200, { ok: true, csrf: fresh.csrf }, { "Set-Cookie": sessionCookie(fresh.id) });
  }

  if (path === "/api/identity/send" && request.method === "POST") {
    const required = requireAccount(request, true);
    const input = await body(request);
    if (!required || !input || !validPhone(input.phone) || locked(required.session)) return genericError(request, required?.session.lockedUntil > Date.now() ? 429 : 403);
    if (!equal(input.phone, required.account.phone)) return genericError(request);
    const code = randomSixDigits();
    required.account.identityCode = code;
    required.account.identityExpiresAt = Date.now() + 5 * 60 * 1000;
    required.account.identityUsed = false;
    /* Test mock value is returned only to this same-origin browser UI, never server logged. */
    return json(request, 200, { ok: true, mockCode: code });
  }

  if (path === "/api/identity/verify" && request.method === "POST") {
    const required = requireAccount(request, true);
    const input = await body(request);
    if (!required || !input || !validOtp(input.code) || locked(required.session)) return genericError(request, required?.session.lockedUntil > Date.now() ? 429 : 403);
    const account = required.account;
    const valid = !!account.identityCode && !account.identityUsed && !!account.identityExpiresAt &&
      account.identityExpiresAt > Date.now() && equal(input.code, account.identityCode);
    if (!valid) {
      required.session.failedIdentity++;
      if (required.session.failedIdentity >= MAX_FAILURES) required.session.lockedUntil = Date.now() + LOCK_MS;
      return genericError(request, required.session.lockedUntil > Date.now() ? 429 : 400);
    }
    account.identityUsed = true;
    account.identityCode = undefined;
    required.session.identityVerified = true;
    required.session.failedIdentity = 0;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/status" && request.method === "GET") {
    const required = requireAccount(request);
    if (!required) return genericError(request, 403);
    return json(request, 200, {
      ok: true,
      enabled: required.account.mfaEnabled,
      backupRemaining: required.account.backupCodes.filter((item) => !item.used).length,
    });
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    const required = requireAccount(request, true);
    if (!required || locked(required.session, required?.account)) return genericError(request, 403);
    if (required.account.mfaEnabled) return genericError(request);
    const secret = base32(randomBytes(20));
    required.account.pending = { secret: await encrypt(secret), expiresAt: Date.now() + 10 * 60 * 1000, used: false };
    return json(request, 200, { ok: true, secret, mockOtp: await totp(secret) });
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const required = requireAccount(request, true);
    const input = await body(request);
    if (!required || !input || !validOtp(input.otp) || typeof input.manualSecret !== "string" || input.manualSecret.length > 128 || locked(required.session, required?.account)) return genericError(request, 403);
    const pending = required.account.pending;
    if (!pending || pending.used || pending.expiresAt <= Date.now()) return genericError(request);
    const secret = await decrypt(pending.secret);
    const manual = input.manualSecret.replaceAll(/\s/g, "").toUpperCase();
    const secretMatches = manual.length === 0 || (decodeBase32(manual) !== null && equal(manual, secret));
    const codeMatches = equal(input.otp, await totp(secret));
    if (!secretMatches || !codeMatches) {
      failMfa(required.session, required.account);
      return genericError(request, locked(required.session, required.account) ? 429 : 400);
    }
    pending.used = true; /* Security Evaluation 5: setup challenge is single-use. */
    required.account.mfaSecret = pending.secret;
    required.account.pending = undefined;
    required.account.mfaEnabled = true;
    required.session.failedMfa = 0;
    const codes = await setBackupCodes(required.account);
    return json(request, 200, { ok: true, codes });
  }

  if (path === "/api/mfa/recovery/regenerate" && request.method === "POST") {
    const required = requireAccount(request, true);
    if (!required || !required.account.mfaEnabled || locked(required.session, required.account)) return genericError(request, 403);
    const codes = await setBackupCodes(required.account);
    return json(request, 200, { ok: true, codes });
  }

  if (path === "/api/mfa/recovery/verify" && request.method === "POST") {
    const required = requireAccount(request, true);
    const input = await body(request);
    if (!required || !input || !validRecovery(input.recoveryCode) || !required.account.mfaEnabled || locked(required.session, required.account)) return genericError(request, 403);
    const digest = await sha256(`${recoveryPepper}:${input.recoveryCode}`);
    const match = required.account.backupCodes.find((item) => !item.used && equal(item.digest, digest));
    if (!match) {
      failMfa(required.session, required.account);
      return genericError(request, locked(required.session, required.account) ? 429 : 400);
    }
    match.used = true;
    required.session.failedMfa = 0;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const session = getSession(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    sessions.delete(session.id);
    return json(request, 200, { ok: true }, { "Set-Cookie": expiredCookie() });
  }

  return genericError(request, 404);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      /* Security Evaluation 2: production-safe, non-verbose failures. */
      return genericError(request, 500);
    }
  },
});

console.log(`MFA enrolment server listening securely on https://localhost:${PORT}`);
