
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const serverPepper = crypto.getRandomValues(new Uint8Array(32));

type SessionPhase = "pending" | "authenticated";
type EncryptedValue = { iv: string; ciphertext: string };
type BackupCode = { hash: string; used: boolean };

type MfaRecord = {
  status: "none" | "provisioning" | "active";
  encryptedTotpSecret?: EncryptedValue;
  lastTotpCounter?: number;
  backupCodes: BackupCode[];
  totpFailures: number;
  totpLockUntil: number;
  recoveryFailures: number;
  recoveryLockUntil: number;
};

type Account = {
  immutableAccountId: string;
  email: string;
  phone: string;
  mfa: MfaRecord;
};

type Session = {
  id: string;
  phase: SessionPhase;
  accountId?: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityCodeHash?: string;
  identityExpiresAt?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockUntil: number;
};

const sessions = new Map<string, Session>();

// Task: server-controlled account records own all persistent MFA configuration.
const accounts = new Map<string, Account>();
const accountByIdentity = new Map<string, string>();
const MARCUS_ACCOUNT_ID = "acct_immutable_marcus_001";

const marcusAccount: Account = {
  immutableAccountId: MARCUS_ACCOUNT_ID,
  email: "marcus@northstar.demo",
  phone: "+15550123456",
  mfa: {
    status: "none",
    backupCodes: [],
    totpFailures: 0,
    totpLockUntil: 0,
    recoveryFailures: 0,
    recoveryLockUntil: 0,
  },
};
accounts.set(marcusAccount.immutableAccountId, marcusAccount);
accountByIdentity.set(`${marcusAccount.email}|${marcusAccount.phone}`, marcusAccount.immutableAccountId);

const SESSION_COOKIE = "__Host-mfa_session";
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const IDENTITY_CODE_LIFETIME_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const VERIFICATION_FAILURE_THRESHOLD = 5;
const MAX_BODY_BYTES = 10_000;

const allowedPaths = new Set([
  "/",
  "/api/session",
  "/api/signin",
  "/api/identity/verify",
  "/api/mfa/provision",
  "/api/mfa/activate",
  "/api/mfa/backup/regenerate",
  "/api/mfa/backup/acknowledge",
  "/api/mfa/recovery/verify",
  "/api/logout",
]);

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function secureInt(maxExclusive: number): number {
  const max = 0x1_0000_0000;
  const limit = max - (max % maxExclusive);
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value);
  while (value[0] >= limit);
  return value[0] % maxExclusive;
}

function sixDigitCode(): string {
  return String(secureInt(1_000_000)).padStart(6, "0");
}

function cookieHeader(value: string, maxAge?: number): string {
  const expires = maxAge === 0
    ? "; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    : "";
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${expires}`;
}

function parseCookies(req: Request): Record<string, string> {
  const output: Record<string, string> = {};
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) output[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return output;
}

function allowedOrigin(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try {
    const requestURL = new URL(req.url);
    const supplied = new URL(origin);
    return supplied.protocol === "https:" &&
      supplied.origin === requestURL.origin &&
      (supplied.hostname === "localhost" ||
        supplied.hostname === "127.0.0.1" ||
        supplied.hostname === "[::1]");
  } catch {
    return false;
  }
}

// Requirements 1 and 5: session expiry removes only session state, never account MFA state.
function getSession(req: Request, requiredPhase?: SessionPhase): Session | null {
  const id = parseCookies(req)[SESSION_COOKIE];
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;

  const now = Date.now();
  if (now - session.lastSeenAt > IDLE_TIMEOUT_MS ||
      now - session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    sessions.delete(id);
    return null;
  }
  if (requiredPhase && session.phase !== requiredPhase) return null;
  session.lastSeenAt = now;
  return session;
}

// Requirements 1 and task: account is resolved exclusively through authenticated session.
function accountForSession(session: Session): Account | null {
  if (session.phase !== "authenticated" || !session.accountId) return null;
  return accounts.get(session.accountId) || null;
}

function csrfValid(req: Request, session: Session): boolean {
  const token = req.headers.get("x-csrf-token");
  return typeof token === "string" &&
    token.length === session.csrf.length &&
    token === session.csrf &&
    allowedOrigin(req);
}

async function hashValue(value: string): Promise<string> {
  const encoded = encoder.encode(value);
  const material = new Uint8Array(serverPepper.length + encoded.length);
  material.set(serverPepper);
  material.set(encoded, serverPepper.length);
  const digest = await crypto.subtle.digest("SHA-256", material);
  return Buffer.from(digest).toString("hex");
}

async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const key = await crypto.subtle.importKey("raw", masterKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return {
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(encrypted).toString("base64"),
  };
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64") },
    key,
    Buffer.from(value.ciphertext, "base64"),
  );
  return decoder.decode(plain);
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function generateBase32Secret(length = 32): string {
  let result = "";
  for (let i = 0; i < length; i++) result += BASE32[secureInt(BASE32.length)];
  return result;
}

function decodeBase32(text: string): Uint8Array {
  let bits = "";
  for (const character of text.replace(/=+$/g, "").toUpperCase()) {
    const index = BASE32.indexOf(character);
    if (index < 0) throw new Error("invalid secret");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

async function totpFor(secret: string, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let counterValue = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(counterValue & 255n);
    counterValue >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const number = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}

function newRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  for (let i = 0; i < 16; i++) {
    if (i === 4 || i === 8 || i === 12) value += "-";
    value += alphabet[secureInt(alphabet.length)];
  }
  return value;
}

async function createBackupCodes(): Promise<{ visible: string[]; stored: BackupCode[] }> {
  const visible: string[] = [];
  const stored: BackupCode[] = [];
  for (let i = 0; i < 8; i++) {
    const code = newRecoveryCode();
    visible.push(code);
    stored.push({ hash: await hashValue(code), used: false });
  }
  return { visible, stored };
}

function headersFor(req: Request, extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Vary", "Origin");
  const origin = req.headers.get("origin");
  if (origin && allowedOrigin(req)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
  }
  return headers;
}

function json(req: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = headersFor(req, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(req: Request, status = 400): Response {
  return json(req, { ok: false, message: "We could not complete that request. Please try again." }, status);
}

// Task: actual stream is bounded before parsing; Content-Length cannot bypass this check.
async function requestBody(req: Request): Promise<Record<string, unknown> | null> {
  if (!(req.headers.get("content-type") || "").toLowerCase().includes("application/json")) return null;
  const declaredLength = req.headers.get("content-length");
  if (declaredLength && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_BODY_BYTES)) return null;
  if (!req.body) return null;

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(next.value);
    }
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const data = JSON.parse(decoder.decode(combined));
    return data && typeof data === "object" && !Array.isArray(data)
      ? data as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function normalizePhone(phone: string): string {
  return phone.replace(/[ ()-]/g, "");
}

function identityKey(email: string, phone: string): string {
  return `${email.trim().toLowerCase()}|${normalizePhone(phone)}`;
}

async function createPendingSession(code: string, matchingAccountId?: string): Promise<Session> {
  const now = Date.now();
  return {
    id: randomToken(),
    phase: "pending",
    // A pending session is bound only when the submitted identity matches a server account.
    accountId: matchingAccountId,
    csrf: randomToken(),
    createdAt: now,
    lastSeenAt: now,
    identityCodeHash: await hashValue(code),
    identityExpiresAt: now + IDENTITY_CODE_LIFETIME_MS,
    identityUsed: false,
    identityFailures: 0,
    identityLockUntil: 0,
  };
}

// Task: rotation changes only session state and retains the immutable server account binding.
function rotateAuthenticatedSession(pending: Session): Session | null {
  if (!pending.accountId || !accounts.has(pending.accountId)) return null;
  const now = Date.now();
  return {
    id: randomToken(),
    phase: "authenticated",
    accountId: pending.accountId,
    csrf: randomToken(),
    createdAt: now,
    lastSeenAt: now,
    identityFailures: 0,
    identityLockUntil: 0,
  };
}

function appHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Northstar Bank MFA enrolment</title>
<style>
:root{--navy:#102a43;--blue:#1769aa;--pale:#eef6fc;--ink:#17212b;--muted:#536574;--danger:#a61b1b;--line:#c9d6df;--ok:#126b42}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:17px/1.48 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{background:var(--navy);color:#fff;padding:18px max(18px,calc((100vw - 600px)/2));box-shadow:0 2px 5px #0003}header strong{font-size:1.15rem}header p{margin:2px 0 0;font-size:.9rem;color:#d9e9f5}main{width:min(100%,600px);margin:0 auto;padding:20px 18px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 2px 8px #102a4310}h1{font-size:1.55rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.2rem;margin:22px 0 8px}p{margin:8px 0 16px}.help{color:var(--muted);font-size:.94rem}.notice{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;border-radius:5px;margin:14px 0}.error{color:var(--danger);font-weight:650;min-height:1.5em}.success{color:var(--ok);font-weight:650}label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;font:inherit;padding:12px;border:2px solid #879aa8;border-radius:8px;background:#fff}input:focus,button:focus{outline:3px solid #f6b73c;outline-offset:2px}button{font:inherit;font-weight:700;border:0;border-radius:8px;padding:12px 16px;margin:12px 6px 0 0;cursor:pointer;background:var(--blue);color:#fff;min-height:48px}button.secondary{background:#e4edf3;color:var(--navy)}button.danger{background:#8c2020}button:disabled{opacity:.6;cursor:wait}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;background:#f1f4f6;padding:10px;border-radius:6px}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:ui-monospace,monospace;font-size:1.04rem;background:#f1f4f6;margin:7px 0;padding:9px 11px;border-radius:6px;letter-spacing:.04em}@media(max-width:380px){body{font-size:16px}.card{padding:17px}main{padding-left:12px;padding-right:12px}}
</style>
</head>
<body>
<header><strong>Northstar Bank</strong><p>Secure MFA enrolment</p></header>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<script>
(() => {
  "use strict";
  let csrf = "", route = "signin", provision = null, visibleCodes = null, identityMockCode = "";
  const app = document.getElementById("app");

  // Required mock delivery disclosures are browser-console-only and dedicated setup screens.
  function disclose(message) { console.log(message); }

  async function api(path, method, body, needsCsrf) {
    const headers = {"Content-Type":"application/json"};
    if (needsCsrf && csrf) headers["X-CSRF-Token"] = csrf;
    try {
      const response = await fetch(path,{method,headers,credentials:"same-origin",body:body ? JSON.stringify(body) : undefined});
      return await response.json();
    } catch (_) {
      return {ok:false,message:"Connection unavailable. Please try again."};
    }
  }
  function message(node,text,okay){node.textContent=text||"";node.className=okay?"success":"error"}

  function renderSignIn() {
    app.innerHTML='<section class="card" aria-labelledby="title"><h1 id="title">Set up secure sign-in</h1><p>Before protected payments can be approved, verify your identity and add an authenticator.</p><div class="notice">Academic demo account: <strong>marcus@northstar.demo</strong><br>Mobile: <strong>+15550123456</strong></div><form id="sign-form" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="email" required><label for="phone">Mobile phone number</label><input id="phone" type="tel" autocomplete="tel" required><p id="form-message" class="error" role="alert"></p><button type="submit">Continue to identity check</button></form></section>';
    document.getElementById("sign-form").addEventListener("submit",async event=>{
      event.preventDefault();const button=event.currentTarget.querySelector("button"),status=document.getElementById("form-message");button.disabled=true;
      const result=await api("/api/signin","POST",{email:document.getElementById("email").value.trim(),phone:document.getElementById("phone").value.trim()},false);button.disabled=false;
      if(!result.ok)return message(status,result.message,false);
      csrf=result.csrf;identityMockCode=result.mockCode;disclose("TEST ONLY — simulated identity verification code: "+identityMockCode);route="verify";render();
    });
  }
  function renderVerify() {
    app.innerHTML='<section class="card" aria-labelledby="verify-title"><h1 id="verify-title">Verify your identity</h1><p>Enter the six-digit code sent to your phone.</p><div class="notice"><strong>Academic test delivery code:</strong><p id="demo-code" class="mono"></p><p class="help">This code is also disclosed in the browser console. It expires in five minutes and can be used once.</p></div><form id="verify-form" novalidate><label for="identity-code">Verification code</label><input id="identity-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p id="verify-message" class="error" role="alert"></p><button type="submit">Verify identity</button><button type="button" class="secondary" id="back">Start again</button></form></section>';
    document.getElementById("demo-code").textContent=identityMockCode;
    document.getElementById("back").onclick=()=>{route="signin";csrf="";identityMockCode="";render()};
    document.getElementById("verify-form").addEventListener("submit",async event=>{
      event.preventDefault();const result=await api("/api/identity/verify","POST",{code:document.getElementById("identity-code").value.trim()},true);
      if(!result.ok)return message(document.getElementById("verify-message"),result.message,false);
      csrf=result.csrf;identityMockCode="";route=result.mfaStatus==="active"?"home":"enrol";render();
    });
  }
  function renderEnrol() {
    app.innerHTML='<section class="card" aria-labelledby="enrol-title"><h1 id="enrol-title">Add an authenticator app</h1><p>An authenticator app produces a new code every 30 seconds.</p><div class="notice"><strong>Accessible option:</strong> enter a setup secret manually. A QR code is not required.</div><p id="enrol-message" class="error" role="alert"></p><button id="create">Create authenticator setup</button><button class="secondary" id="logout">Log out</button></section>';
    document.getElementById("logout").onclick=logout;
    document.getElementById("create").onclick=async event=>{
      event.currentTarget.disabled=true;const result=await api("/api/mfa/provision","POST",{},true);
      if(!result.ok){event.currentTarget.disabled=false;return message(document.getElementById("enrol-message"),result.message,false)}
      provision=result;disclose("TEST ONLY — authenticator manual secret: "+result.manualSecret);disclose("TEST ONLY — authenticator provisioning URI: "+result.provisioningUri);disclose("TEST ONLY — current authenticator code: "+result.mockCurrentCode);route="activate";render();
    };
  }
  function renderActivate() {
    if(!provision){route="enrol";return render()}
    app.innerHTML='<section class="card" aria-labelledby="activate-title"><h1 id="activate-title">Connect your authenticator</h1><p>Add an account manually in your authenticator app with this setup secret:</p><p id="secret" class="mono"></p><div class="notice"><strong>Academic test code:</strong><p id="current-code" class="mono"></p></div><label for="totp">Authenticator code</label><input id="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><p id="activate-message" class="error" role="alert"></p><button id="activate">Activate MFA</button><button class="secondary" id="cancel">Cancel setup</button></section>';
    document.getElementById("secret").textContent=provision.manualSecret;document.getElementById("current-code").textContent=provision.mockCurrentCode;
    document.getElementById("cancel").onclick=()=>{provision=null;route="enrol";render()};
    document.getElementById("activate").onclick=async event=>{
      event.currentTarget.disabled=true;const result=await api("/api/mfa/activate","POST",{code:document.getElementById("totp").value.trim()},true);
      if(!result.ok){event.currentTarget.disabled=false;return message(document.getElementById("activate-message"),result.message,false)}
      provision=null;visibleCodes=result.backupCodes;disclose("TEST ONLY — newly issued backup recovery codes: "+result.backupCodes.join(", "));route="codes";render();
    };
  }
  function renderCodes() {
    if(!Array.isArray(visibleCodes)){route="home";return render()}
    app.innerHTML='<section class="card" aria-labelledby="codes-title"><h1 id="codes-title">Save your recovery codes</h1><p>These one-use codes are displayed only once. Store them somewhere private.</p><ul id="code-list" class="codes"></ul><div class="notice">Do not share these codes with anyone, including bank staff.</div><p id="codes-message" class="error" role="alert"></p><button id="saved">I have saved these codes</button></section>';
    const list=document.getElementById("code-list");visibleCodes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.appendChild(li)});
    document.getElementById("saved").onclick=async()=>{const result=await api("/api/mfa/backup/acknowledge","POST",{},true);if(!result.ok)return message(document.getElementById("codes-message"),result.message,false);visibleCodes=null;route="home";render()};
  }
  function renderHome() {
    app.innerHTML='<section class="card" aria-labelledby="home-title"><h1 id="home-title">MFA is active</h1><p class="success">Your authenticator is ready for protected payments.</p><h2>Use a recovery code</h2><form id="recovery-form"><label for="recovery-code">Recovery code</label><input id="recovery-code" autocomplete="off" autocapitalize="characters" placeholder="ABCD-EFGH-IJKL-MNPQ"><p id="recovery-message" class="error" role="alert"></p><button type="submit">Verify recovery code</button></form><h2>Need a new set?</h2><p class="help">Generating new codes permanently invalidates all previous recovery codes.</p><button class="secondary" id="regenerate">Generate new recovery codes</button><button class="danger" id="logout">Log out</button></section>';
    document.getElementById("logout").onclick=logout;
    document.getElementById("recovery-form").addEventListener("submit",async event=>{event.preventDefault();const result=await api("/api/mfa/recovery/verify","POST",{code:document.getElementById("recovery-code").value.trim()},true);message(document.getElementById("recovery-message"),result.message,result.ok)});
    document.getElementById("regenerate").onclick=async event=>{event.currentTarget.disabled=true;const result=await api("/api/mfa/backup/regenerate","POST",{},true);if(!result.ok){event.currentTarget.disabled=false;return}visibleCodes=result.backupCodes;disclose("TEST ONLY — regenerated backup recovery codes: "+result.backupCodes.join(", "));route="codes";render()};
  }
  async function logout(){await api("/api/logout","POST",{},true);csrf="";provision=null;visibleCodes=null;identityMockCode="";route="signin";console.log("Signed out. The secure session was invalidated.");render()}
  function render(){if(route==="signin")renderSignIn();else if(route==="verify")renderVerify();else if(route==="enrol")renderEnrol();else if(route==="activate")renderActivate();else if(route==="codes")renderCodes();else renderHome()}
  async function boot(){const state=await api("/api/session","GET",null,false);if(state.ok&&state.phase!=="signedout"){csrf=state.csrf||"";route=state.phase==="pending"?"verify":state.mfaStatus==="active"?"home":"enrol"}render()}boot();
})();
</script>
</body>
</html>`;
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.protocol !== "https:" || !allowedPaths.has(url.pathname) || url.search) return genericError(req, 404);

  if (req.method === "OPTIONS") {
    if (!allowedOrigin(req)) return genericError(req, 403);
    const headers = headersFor(req);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Max-Age", "600");
    return new Response(null, { status: 204, headers });
  }

  if (url.pathname === "/" && req.method === "GET") {
    const headers = headersFor(req);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(appHtml(), { status: 200, headers });
  }

  if (url.pathname === "/api/session" && req.method === "GET") {
    const session = getSession(req);
    if (!session) return json(req, { ok: true, phase: "signedout" });
    const account = accountForSession(session);
    return json(req, {
      ok: true,
      phase: session.phase,
      csrf: session.csrf,
      mfaStatus: account?.mfa.status || "none",
    });
  }

  if (req.method !== "POST" || !allowedOrigin(req)) return genericError(req, 403);
  const body = await requestBody(req);
  if (!body) return genericError(req);

  if (url.pathname === "/api/signin") {
    if (!validEmail(body.email) || !validPhone(body.phone)) return genericError(req);
    const verificationCode = sixDigitCode();
    const matchedAccountId = accountByIdentity.get(identityKey(body.email, body.phone));
    const pending = await createPendingSession(verificationCode, matchedAccountId);
    sessions.set(pending.id, pending);

    // Same successful response shape/code delivery for matched and unmatched identities avoids enumeration.
    return json(req, {
      ok: true,
      csrf: pending.csrf,
      mockCode: verificationCode,
      message: "If the details can be used, a verification code has been sent.",
    }, 200, { "Set-Cookie": cookieHeader(pending.id) });
  }

  if (url.pathname === "/api/identity/verify") {
    const pending = getSession(req, "pending");
    if (!pending || !csrfValid(req, pending)) return genericError(req, 403);
    const now = Date.now();
    if (pending.identityLockUntil > now) return genericError(req, 429);

    const correct = validOtp(body.code) &&
      !pending.identityUsed &&
      !!pending.identityExpiresAt &&
      now <= pending.identityExpiresAt &&
      await hashValue(String(body.code)) === pending.identityCodeHash &&
      !!pending.accountId &&
      accounts.has(pending.accountId);

    if (!correct) {
      pending.identityFailures++;
      if (pending.identityFailures >= VERIFICATION_FAILURE_THRESHOLD) pending.identityLockUntil = now + LOCKOUT_MS;
      return genericError(req, pending.identityLockUntil > now ? 429 : 400);
    }

    pending.identityUsed = true;
    const authenticated = rotateAuthenticatedSession(pending);
    if (!authenticated) return genericError(req, 403);
    sessions.delete(pending.id);
    sessions.set(authenticated.id, authenticated);
    const account = accountForSession(authenticated)!;
    return json(req, { ok: true, csrf: authenticated.csrf, mfaStatus: account.mfa.status }, 200, {
      "Set-Cookie": cookieHeader(authenticated.id),
    });
  }

  if (url.pathname === "/api/logout") {
    const session = getSession(req);
    if (!session || !csrfValid(req, session)) return genericError(req, 403);
    sessions.delete(session.id);
    return json(req, { ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });
  }

  const session = getSession(req, "authenticated");
  if (!session || !csrfValid(req, session)) return genericError(req, 403);
  const account = accountForSession(session);
  if (!account) return genericError(req, 403);
  const mfa = account.mfa;

  if (url.pathname === "/api/mfa/provision") {
    const secret = generateBase32Secret();
    mfa.encryptedTotpSecret = await encryptSecret(secret);
    mfa.status = "provisioning";
    mfa.lastTotpCounter = undefined;
    mfa.totpFailures = 0;
    mfa.totpLockUntil = 0;
    const currentCode = await totpFor(secret, Math.floor(Date.now() / 30_000));
    const accountLabel = encodeURIComponent("Northstar Bank:Marcus");
    const issuer = encodeURIComponent("Northstar Bank");
    return json(req, {
      ok: true,
      manualSecret: secret,
      provisioningUri: `otpauth://totp/${accountLabel}?secret=${secret}&issuer=${issuer}&period=30&digits=6`,
      mockCurrentCode: currentCode,
    });
  }

  if (url.pathname === "/api/mfa/activate") {
    const now = Date.now();
    if (mfa.totpLockUntil > now) return genericError(req, 429);
    const failed = (): Response => {
      mfa.totpFailures++;
      if (mfa.totpFailures >= VERIFICATION_FAILURE_THRESHOLD) mfa.totpLockUntil = now + LOCKOUT_MS;
      return genericError(req, mfa.totpLockUntil > now ? 429 : 400);
    };

    if (!mfa.encryptedTotpSecret || mfa.status !== "provisioning" || !validOtp(body.code)) return failed();
    const secret = await decryptSecret(mfa.encryptedTotpSecret);
    const baseCounter = Math.floor(now / 30_000);
    let matchedCounter: number | null = null;
    for (const candidate of [baseCounter - 1, baseCounter, baseCounter + 1]) {
      if (candidate >= 0 && await totpFor(secret, candidate) === body.code) {
        matchedCounter = candidate;
        break;
      }
    }
    if (matchedCounter === null || mfa.lastTotpCounter === matchedCounter) return failed();

    mfa.lastTotpCounter = matchedCounter;
    mfa.totpFailures = 0;
    mfa.totpLockUntil = 0;
    const backups = await createBackupCodes();
    mfa.backupCodes = backups.stored;
    mfa.status = "active";
    return json(req, { ok: true, backupCodes: backups.visible });
  }

  if (url.pathname === "/api/mfa/backup/regenerate") {
    if (mfa.status !== "active") return genericError(req);
    const backups = await createBackupCodes();
    mfa.backupCodes = backups.stored;
    return json(req, { ok: true, backupCodes: backups.visible });
  }

  if (url.pathname === "/api/mfa/backup/acknowledge") {
    if (mfa.status !== "active") return genericError(req);
    return json(req, { ok: true });
  }

  if (url.pathname === "/api/mfa/recovery/verify") {
    const now = Date.now();
    if (mfa.recoveryLockUntil > now) return genericError(req, 429);
    const failed = (): Response => {
      mfa.recoveryFailures++;
      if (mfa.recoveryFailures >= VERIFICATION_FAILURE_THRESHOLD) mfa.recoveryLockUntil = now + LOCKOUT_MS;
      return genericError(req, mfa.recoveryLockUntil > now ? 429 : 400);
    };

    if (mfa.status !== "active" || typeof body.code !== "string") return failed();
    const code = body.code.trim().toUpperCase();
    if (!/^[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}$/.test(code)) return failed();

    const candidate = await hashValue(code);
    const stored = mfa.backupCodes.find(item => !item.used && item.hash === candidate);
    if (!stored) return failed();

    stored.used = true;
    mfa.recoveryFailures = 0;
    mfa.recoveryLockUntil = 0;
    return json(req, { ok: true, message: "Recovery code accepted. It cannot be used again." });
  }

  return genericError(req, 404);
}

const port = Number(Bun.env.PORT || 3000);

// Requirement 3: TLS is mandatory and uses the required local mkcert paths.
Bun.serve({
  hostname: "0.0.0.0",
  port,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(req) {
    try {
      return await handle(req);
    } catch {
      return genericError(req, 500);
    }
  },
});
