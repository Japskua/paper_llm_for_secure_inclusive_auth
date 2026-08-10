
/*
  One-file Bun HTTPS server + inline vanilla-JS mobile SPA.
  Requirements 1–5: deterministic in-memory mock state, no external requests,
  no browser storage, server-side authorization, TLS, CSRF, and secure mocks.
*/

const port = Number(Bun.env.PORT || 3000);
const sessions = new Map<string, Session>();
const identityStates = new Map<string, IdentityState>();
const masterKey = randomBytes(32);
const recoveryPepper = toBase64Url(randomBytes(32));
const encoder = new TextEncoder();

type AttemptKind = "identity" | "authenticator" | "recovery";
type Attempt = { count: number; lockedUntil: number };
type Attempts = Record<AttemptKind, Attempt>;
type EncryptedValue = { iv: string; ciphertext: string };

type IdentityState = {
  target: string;
  account?: "marcus";
  challenge: { code: string; expiresAt: number; used: boolean };
  attempts: Attempt;
};

type Session = {
  id: string;
  csrf: string;
  account?: "marcus";
  identityTarget?: string;
  stage: "anonymous" | "identity" | "verified" | "provisioned" | "mfa";
  createdAt: number;
  lastSeen: number;
  encryptedSecret?: EncryptedValue;
  authenticatorUsed?: boolean;
  recoveryHashes: string[];
  pendingRecoveryDisplay?: string[];
  recoveryVerifiedUntil?: number;
  attempts: Attempts;
};

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const RECOVERY_GRANT_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;

/* Mock account table: lookup is server-side and never accepts a client user ID. */
const MARCUS_ACCOUNT = {
  id: "marcus" as const,
  email: "marcus@example.test",
  phone: "+447700900123",
};

const TRUSTED_ORIGINS = new Set([
  `https://localhost:${port}`,
  `https://127.0.0.1:${port}`,
  `https://[::1]:${port}`,
]);

function randomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function secureEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) difference |= (left[i] || 0) ^ (right[i] || 0);
  return difference === 0;
}

function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "", buffer = 0, bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}

function randomDecimalCode(): string {
  let code = "";
  while (code.length < 6) {
    const byte = randomBytes(1)[0];
    if (byte < 250) code += String(byte % 10);
  }
  return code;
}

function randomRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "";
  while (result.length < 10) {
    const byte = randomBytes(1)[0];
    if (byte < 248) result += alphabet[byte % alphabet.length];
  }
  return `${result.slice(0, 5)}-${result.slice(5)}`;
}

async function sha256(value: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

/* Requirement 3: AES-GCM protects pending authenticator secrets at rest. */
async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: toBase64Url(iv), ciphertext: toBase64Url(new Uint8Array(ciphertext)) };
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(value.iv) },
    key,
    fromBase64Url(value.ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}

/* Deterministic mock TOTP for the current two-minute evaluation window. */
async function totp(secret: string): Promise<string> {
  const counter = Math.floor(Date.now() / 120000);
  const counterBytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = value & 255;
    value = Math.floor(value / 256);
  }
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const numeric = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3];
  return String(numeric % 1000000).padStart(6, "0");
}

function newAttempts(): Attempts {
  return {
    identity: { count: 0, lockedUntil: 0 },
    authenticator: { count: 0, lockedUntil: 0 },
    recovery: { count: 0, lockedUntil: 0 },
  };
}

function newSession(stage: Session["stage"] = "anonymous"): Session {
  const now = Date.now();
  return {
    id: toBase64Url(randomBytes(32)),
    csrf: toBase64Url(randomBytes(32)),
    stage,
    createdAt: now,
    lastSeen: now,
    recoveryHashes: [],
    attempts: newAttempts(),
  };
}

function normalizeEmail(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase().slice(0, 254) : "";
}

function normalizePhone(value: unknown): string {
  return typeof value === "string" ? value.replace(/[ ()-]/g, "").trim().slice(0, 32) : "";
}

/*
 Requirement 4: input is normalized and bounded before lookup. The opaque target
 binds persistent identity rate limiting to either Marcus or this normalized target.
*/
function identityTarget(email: unknown, phone: unknown): { target: string; account?: "marcus" } {
  const normalizedEmail = normalizeEmail(email);
  const normalizedPhone = normalizePhone(phone);
  const target = `email:${normalizedEmail}|phone:${normalizedPhone}`;
  const isMarcus = secureEqual(normalizedEmail, MARCUS_ACCOUNT.email) &&
    secureEqual(normalizedPhone, MARCUS_ACCOUNT.phone);
  return { target, account: isMarcus ? "marcus" : undefined };
}

function cookieFor(session: Session): string {
  return `mfa_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function cookieValue(request: Request, name: string): string | undefined {
  const raw = request.headers.get("cookie") || "";
  const part = raw.split(";").map((item) => item.trim()).find((item) => item.startsWith(`${name}=`));
  return part?.slice(name.length + 1);
}

/* Requirement 1/5: opaque account-bound server session, checked on every endpoint. */
function sessionFrom(request: Request): Session | undefined {
  const id = cookieValue(request, "mfa_session");
  if (!id || !/^[A-Za-z0-9_-]{32,64}$/.test(id)) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}

function baseHeaders(): Headers {
  const headers = new Headers();
  headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return headers;
}

function corsHeaders(request: Request, headers: Headers): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  if (!TRUSTED_ORIGINS.has(origin)) return false;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Vary", "Origin");
  return true;
}

function json(data: unknown, status = 200, cookie?: string, request?: Request): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (request) corsHeaders(request, headers);
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400, request?: Request): Response {
  return json({ error: "Unable to complete this request. Please try again." }, status, undefined, request);
}

function recoveryUnavailable(request: Request): Response {
  return json({ error: "Recovery codes are unavailable. Return to MFA settings." }, 409, undefined, request);
}

function validCsrf(value: unknown, session: Session): boolean {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,64}$/.test(value) && secureEqual(value, session.csrf);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | undefined> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return undefined;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function allowedRedirect(value: unknown): boolean {
  return value === undefined || value === "/" || value === "/settings" || value === "#settings";
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}
function validSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{16,80}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(value);
}

function mayAttempt(attempt: Attempt): boolean {
  return attempt.lockedUntil <= Date.now();
}

function failedAttempt(attempt: Attempt): void {
  attempt.count++;
  if (attempt.count >= 5) {
    attempt.count = 0;
    attempt.lockedUntil = Date.now() + LOCKOUT_MS;
  }
}

function successfulAttempt(attempt: Attempt): void {
  attempt.count = 0;
  attempt.lockedUntil = 0;
}

function authenticated(session: Session | undefined): session is Session {
  return !!session?.account;
}

function generateRecoveryCodes(): string[] {
  return Array.from({ length: 8 }, randomRecoveryCode);
}

/* Requirement 3: only one-way values persist after a recovery-code display. */
async function setRecoveryCodes(session: Session): Promise<void> {
  const plaintext = generateRecoveryCodes();
  session.recoveryHashes = await Promise.all(plaintext.map((code) => sha256(`${recoveryPepper}:${code}`)));
  session.pendingRecoveryDisplay = plaintext;
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA enrolment</title>
<style>
:root{--navy:#102a43;--blue:#1769aa;--pale:#edf6ff;--line:#c8d6e5;--ink:#172b4d;--good:#106b45;--danger:#a52a2a}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:16px/1.45 system-ui,sans-serif}header{background:var(--navy);color:#fff;padding:18px 20px}header h1{font-size:1.15rem;margin:0}header p{margin:3px 0 0;font-size:.88rem;color:#d9e9f6}main{max-width:570px;margin:auto;padding:18px 14px 42px}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px;margin:0 0 15px;box-shadow:0 1px 2px #102a4312}h2{font-size:1.35rem;line-height:1.2;margin:0 0 10px}.muted{color:#52677d;font-size:.93rem}.notice{background:var(--pale);border-left:4px solid var(--blue);padding:10px 12px;margin:14px 0;border-radius:4px}.warning{background:#fff7df;border-left-color:#a86d00}.success{background:#e9f8ef;border-left-color:var(--good)}label{display:block;font-weight:650;margin:13px 0 5px}input{width:100%;font:inherit;padding:11px;border:1px solid #8fa6ba;border-radius:7px;color:var(--ink)}button{font:inherit;font-weight:700;padding:11px 15px;border:0;border-radius:7px;background:var(--blue);color:#fff;margin-top:17px;min-height:45px;cursor:pointer}button.secondary{background:#e6eef5;color:#173d60}button.danger{background:#a52a2a}.actions{display:flex;gap:9px;flex-wrap:wrap}.view[hidden],.detail[hidden]{display:none}.code{display:block;overflow-wrap:anywhere;background:#f3f7fa;border:1px solid var(--line);border-radius:6px;padding:9px;font:14px ui-monospace,monospace}.codes{padding-left:22px;font:16px ui-monospace,monospace}.codes li{padding:4px 0}.error{color:var(--danger);font-weight:650;min-height:1.45em}.status{color:var(--good);font-weight:650;min-height:1.45em}a{color:#075b9c;text-decoration:underline;cursor:pointer}#logs{background:#081725;color:#d5f1ff;border-radius:8px;padding:10px;min-height:78px;max-height:180px;overflow:auto;font:12px/1.4 ui-monospace,monospace;white-space:pre-wrap}footer{font-size:.8rem;color:#52677d;text-align:center;padding:8px}
</style>
</head>
<body>
<header><h1>Harbour Bank</h1><p>Secure multi-factor authentication enrolment</p></header>
<main>
<section id="signin" class="view card"><h2>Sign in to begin</h2><p class="muted">Confirm your bank account details before enrolling MFA.</p><form id="signin-form" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="email" value="marcus@example.test" required><label for="phone">Mobile number</label><input id="phone" type="tel" autocomplete="tel" value="+44 7700 900123" required><p id="signin-error" class="error" role="alert"></p><button>Continue securely</button></form></section>
<section id="identity" class="view card" hidden><h2>Verify your identity</h2><p>Enter the six-digit code sent to your verified contact method.</p><div class="notice">The protected mock delivery code is shown only in the Logs panel and browser console.</div><form id="identity-form"><label for="identity-code">Verification code</label><input id="identity-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p id="identity-error" class="error" role="alert"></p><button>Verify identity</button></form></section>
<section id="setup" class="view card" hidden><h2>Set up an authenticator app</h2><p>Use an authenticator app to generate a code when approving higher-value payments.</p><div id="provision-start"><button id="provision-button" type="button">Create authenticator setup</button></div><div id="provision-detail" class="detail" hidden><div class="notice success"><strong>Authenticator created.</strong> Add this value manually. Pending setup can be resumed securely after a refresh.</div><label>Manual setup secret</label><output id="setup-secret" class="code"></output><label>Provisioning value</label><output id="provision-uri" class="code"></output><form id="authenticator-form"><label for="manual-secret">Manual secret (confirm setup)</label><input id="manual-secret" autocomplete="off" spellcheck="false" required><label for="auth-code">Authenticator code</label><input id="auth-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p id="auth-error" class="error" role="alert"></p><button>Enable authenticator MFA</button></form></div></section>
<section id="recovery" class="view card" hidden><h2>Save your recovery codes</h2><div class="notice warning"><strong>Shown once.</strong> Copy these codes now and store them safely. Each code can be used once.</div><p id="recovery-state" class="muted"></p><ul id="recovery-list" class="codes"></ul><p id="recovery-error" class="error" role="alert"></p><button id="recovery-finish" type="button">I have saved my codes</button></section>
<section id="settings" class="view card" hidden><h2>MFA settings</h2><p id="settings-status" class="status"></p><div class="notice">Your authenticator is enabled. Recovery codes are retained only as protected one-way verification values.</div><div class="actions"><button id="open-recovery-check" class="secondary" type="button">Regenerate recovery codes</button><button id="logout-button" class="danger" type="button">Log out</button></div></section>
<section id="recover-verify" class="view card" hidden><h2>Confirm with a recovery code</h2><p>To generate a replacement set, enter one unused recovery code. It will be consumed.</p><form id="recovery-verify-form"><label for="recovery-code">Recovery code</label><input id="recovery-code" placeholder="ABCDE-23456" autocapitalize="characters" autocomplete="off" required><p id="recover-verify-error" class="error" role="alert"></p><button>Verify recovery code</button></form><div id="regen-action" class="detail" hidden><div class="notice success">Recovery code confirmed. You may now replace your set.</div><button id="regenerate-button" type="button">Generate replacement codes</button></div><p><a id="back-settings">Back to MFA settings</a></p></section>
<section class="card"><h2>Logs</h2><p class="muted">Mock delivery and recovery values for evaluation.</p><div id="logs" aria-live="polite">Ready.</div></section>
<footer>Protected HTTPS session · Do not share verification or recovery codes.</footer>
</main>
<script>
(() => {
  let csrf="";
  const views=["signin","identity","setup","recovery","settings","recover-verify"];
  const $=id=>document.getElementById(id), logBox=$("logs");
  function log(message){console.log(message);const line=document.createElement("div");line.textContent=message;logBox.appendChild(line);logBox.scrollTop=logBox.scrollHeight}
  function show(name){views.forEach(id=>$(id).hidden=id!==name);document.querySelector("main").scrollIntoView({behavior:"smooth",block:"start"})}
  function error(id,message){$(id).textContent=message||""}
  function clearErrors(){document.querySelectorAll(".error").forEach(node=>node.textContent="")}
  function text(node,value){node.textContent=String(value||"")}
  async function api(path,options={}){
    const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:options.body?{"Content-Type":"application/json"}:{},body:options.body?JSON.stringify(options.body):undefined});
    let data={};try{data=await response.json()}catch(_){}
    if(data.csrf)csrf=data.csrf;
    if(!response.ok){const failure=new Error(data.error||"Unable to complete this request. Please try again.");failure.status=response.status;throw failure}
    return data
  }
  function renderProvisioning(data){
    text($("setup-secret"),data.secret);text($("provision-uri"),data.provisioning);$("manual-secret").value=data.secret||"";
    $("provision-detail").hidden=false;$("provision-start").hidden=true;
    /* Secret is deliberately never logged or mirrored to the Logs panel. */
    if(data.testOtp)log("Mock authenticator OTP: "+data.testOtp)
  }
  async function boot(){
    try{const data=await api("/api/bootstrap");
      if(data.view==="settings")await loadSettings();
      else if(data.view==="recovery")await loadRecoveryCodes();
      else if(data.view==="identity")show("identity");
      else if(data.view==="setup"){show("setup");if(data.pendingSetup)renderProvisioning(data.pendingSetup)}
      else show("signin")
    }catch(_){error("signin-error","Secure connection could not be established.");show("signin")}
  }
  async function loadSettings(){try{const data=await api("/api/mfa/settings");text($("settings-status"),data.enabled?"Authenticator MFA is active.":"");show("settings")}catch(_){show("signin");error("signin-error","Please sign in again.")}}
  $("signin-form").addEventListener("submit",async event=>{event.preventDefault();clearErrors();try{const data=await api("/api/signin",{method:"POST",body:{csrf,email:$("email").value.trim(),phone:$("phone").value.trim(),redirect:"#setup"}});log("Mock identity verification code: "+data.testOtp);show("identity")}catch(err){error("signin-error",err.message)}});
  $("identity-form").addEventListener("submit",async event=>{event.preventDefault();clearErrors();try{await api("/api/identity/verify",{method:"POST",body:{csrf,otp:$("identity-code").value.trim()}});show("setup")}catch(err){error("identity-error",err.message)}});
  $("provision-button").addEventListener("click",async()=>{clearErrors();try{renderProvisioning(await api("/api/authenticator/provision",{method:"POST",body:{csrf}}))}catch(err){error("auth-error",err.message)}});
  $("authenticator-form").addEventListener("submit",async event=>{event.preventDefault();clearErrors();try{await api("/api/authenticator/confirm",{method:"POST",body:{csrf,secret:$("manual-secret").value.trim().toUpperCase(),otp:$("auth-code").value.trim()}});await loadRecoveryCodes()}catch(err){error("auth-error",err.message)}});
  async function loadRecoveryCodes(){
    const list=$("recovery-list");list.replaceChildren();text($("recovery-state"),"");error("recovery-error","");
    try{const data=await api("/api/recovery-codes");data.codes.forEach(code=>{const item=document.createElement("li");item.textContent=code;list.appendChild(item)});log("Mock recovery codes: "+data.codes.join(", "));show("recovery")}
    catch(err){if(err.status===409){text($("recovery-state"),"These recovery codes have already been displayed or are unavailable.");show("recovery")}else await loadSettings()}
  }
  $("recovery-finish").addEventListener("click",loadSettings);
  $("open-recovery-check").addEventListener("click",()=>{$("regen-action").hidden=true;$("recovery-code").value="";clearErrors();show("recover-verify")});
  $("back-settings").addEventListener("click",loadSettings);
  $("recovery-verify-form").addEventListener("submit",async event=>{event.preventDefault();clearErrors();try{await api("/api/recovery/verify",{method:"POST",body:{csrf,code:$("recovery-code").value.trim().toUpperCase()}});$("regen-action").hidden=false}catch(err){error("recover-verify-error",err.message)}});
  $("regenerate-button").addEventListener("click",async()=>{try{await api("/api/recovery/regenerate",{method:"POST",body:{csrf}});await loadRecoveryCodes()}catch(err){error("recover-verify-error",err.message)}});
  $("logout-button").addEventListener("click",async()=>{try{await api("/api/logout",{method:"POST",body:{csrf}})}catch(_){}csrf="";$("provision-detail").hidden=true;$("provision-start").hidden=false;$("manual-secret").value="";show("signin");log("Session logged out.")});
  boot()
})();
</script>
</body>
</html>`;

async function pendingSetupPayload(session: Session): Promise<{ secret: string; provisioning: string; testOtp: string } | undefined> {
  if (session.stage !== "provisioned" || !session.encryptedSecret) return undefined;
  const secret = await decryptSecret(session.encryptedSecret);
  return {
    secret,
    provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`,
    testOtp: await totp(secret),
  };
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const headers = baseHeaders();
  if (!corsHeaders(request, headers)) return genericError(403, request);

  if (request.method === "OPTIONS") {
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers });
  }

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    let session = sessionFrom(request);
    let cookie: string | undefined;
    if (!session) {
      session = newSession();
      sessions.set(session.id, session);
      cookie = cookieFor(session);
    }
    if (session.stage === "provisioned") {
      return json({ csrf: session.csrf, view: "setup", pendingSetup: await pendingSetupPayload(session) }, 200, cookie, request);
    }
    const view = session.stage === "mfa" ? (session.pendingRecoveryDisplay ? "recovery" : "settings") :
      session.stage === "identity" ? "identity" : session.stage === "verified" ? "setup" : "signin";
    return json({ csrf: session.csrf, view }, 200, cookie, request);
  }

  const session = sessionFrom(request);
  if (!session) return genericError(401, request);

  if (pathname === "/api/mfa/settings" && request.method === "GET") {
    if (!authenticated(session) || session.stage !== "mfa") return genericError(403, request);
    return json({ csrf: session.csrf, enabled: true }, 200, undefined, request);
  }

  if (pathname === "/api/recovery-codes" && request.method === "GET") {
    if (!authenticated(session) || session.stage !== "mfa") return genericError(403, request);
    const codes = session.pendingRecoveryDisplay;
    if (!codes?.length) return recoveryUnavailable(request);
    session.pendingRecoveryDisplay = undefined;
    return json({ csrf: session.csrf, codes }, 200, undefined, request);
  }

  if (request.method !== "POST") return genericError(404, request);
  const body = await requestBody(request);
  if (!body || !validCsrf(body.csrf, session)) return genericError(403, request);

  /*
    Task: account lookup happens only server-side. Valid and invalid normalized
    identities receive the same rotated-session response shape and timing class.
    Invalid identities receive a non-account identity target, never Marcus access.
  */
  if (pathname === "/api/signin") {
    if (session.stage !== "anonymous" || !allowedRedirect(body.redirect)) return genericError(400, request);
    const resolved = identityTarget(body.email, body.phone);
    let state = identityStates.get(resolved.target);
    if (!state) {
      state = {
        target: resolved.target,
        account: resolved.account,
        challenge: { code: randomDecimalCode(), expiresAt: Date.now() + CHALLENGE_MS, used: false },
        attempts: { count: 0, lockedUntil: 0 },
      };
      identityStates.set(resolved.target, state);
    } else {
      /* Restarting creates a fresh time-bound code but deliberately retains lockout state. */
      state.challenge = { code: randomDecimalCode(), expiresAt: Date.now() + CHALLENGE_MS, used: false };
    }

    sessions.delete(session.id);
    const rotated = newSession("identity");
    rotated.identityTarget = state.target;
    sessions.set(rotated.id, rotated);

    /* Generic identical response prevents account enumeration in client-visible output. */
    return json({ csrf: rotated.csrf, testOtp: state.challenge.code }, 200, cookieFor(rotated), request);
  }

  /*
    Task: malformed OTPs increment the persistent target counter just like wrong OTPs.
    The target is retained independently of browser sessions, preventing reset bypass.
  */
  if (pathname === "/api/identity/verify") {
    const state = session.stage === "identity" && session.identityTarget ? identityStates.get(session.identityTarget) : undefined;
    if (!state) return genericError(400, request);
    if (!mayAttempt(state.attempts)) return genericError(400, request);
    const valid = validOtp(body.otp);
    const challenge = state.challenge;
    if (!valid || challenge.used || challenge.expiresAt < Date.now() || !secureEqual(String(body.otp), challenge.code) || !state.account) {
      failedAttempt(state.attempts);
      return genericError(400, request);
    }
    challenge.used = true;
    successfulAttempt(state.attempts);
    session.account = state.account;
    session.stage = "verified";
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (!authenticated(session)) return genericError(401, request);

  if (pathname === "/api/authenticator/provision") {
    if (session.stage !== "verified") return genericError(400, request);
    const secret = base32(randomBytes(20));
    session.encryptedSecret = await encryptSecret(secret);
    session.authenticatorUsed = false;
    session.stage = "provisioned";
    return json({
      csrf: session.csrf,
      secret,
      provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`,
      testOtp: await totp(secret),
    }, 200, undefined, request);
  }

  /*
    Task: malformed authenticator entries consume the same five-attempt budget.
    Eligibility is checked first so unrelated requests cannot affect MFA counters.
  */
  if (pathname === "/api/authenticator/confirm") {
    if (session.stage !== "provisioned" || !session.encryptedSecret) return genericError(400, request);
    const attempt = session.attempts.authenticator;
    if (!mayAttempt(attempt)) return genericError(400, request);
    if (!validSecret(body.secret) || !validOtp(body.otp)) {
      failedAttempt(attempt);
      return genericError(400, request);
    }
    const storedSecret = await decryptSecret(session.encryptedSecret);
    const expectedOtp = await totp(storedSecret);
    if (session.authenticatorUsed || !secureEqual(body.secret, storedSecret) || !secureEqual(body.otp, expectedOtp)) {
      failedAttempt(attempt);
      return genericError(400, request);
    }
    session.authenticatorUsed = true;
    successfulAttempt(attempt);
    session.stage = "mfa";
    await setRecoveryCodes(session);
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  /* Task: malformed recovery code entries also consume the same five-attempt budget. */
  if (pathname === "/api/recovery/verify") {
    if (session.stage !== "mfa") return genericError(400, request);
    const attempt = session.attempts.recovery;
    if (!mayAttempt(attempt)) return genericError(400, request);
    if (!validRecovery(body.code)) {
      failedAttempt(attempt);
      return genericError(400, request);
    }
    const candidate = await sha256(`${recoveryPepper}:${body.code}`);
    const index = session.recoveryHashes.findIndex((hash) => secureEqual(hash, candidate));
    if (index === -1) {
      failedAttempt(attempt);
      return genericError(400, request);
    }
    session.recoveryHashes.splice(index, 1);
    session.recoveryVerifiedUntil = Date.now() + RECOVERY_GRANT_MS;
    successfulAttempt(attempt);
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/recovery/regenerate") {
    if (session.stage !== "mfa" || !session.recoveryVerifiedUntil || session.recoveryVerifiedUntil < Date.now()) {
      return genericError(400, request);
    }
    session.recoveryVerifiedUntil = undefined;
    await setRecoveryCodes(session);
    return json({ csrf: session.csrf, ok: true }, 200, undefined, request);
  }

  if (pathname === "/api/logout") {
    sessions.delete(session.id);
    return json({ ok: true }, 200, expiredCookie(), request);
  }

  return genericError(404, request);
}

async function fetchHandler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
    if (url.pathname === "/" && request.method === "GET") {
      const headers = baseHeaders();
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page, { status: 200, headers });
    }
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch {
    /* Requirement 2: production-safe generic errors without stack traces. */
    return new Response("Unable to complete this request.", { status: 500, headers: baseHeaders() });
  }
}

/* Requirement 2/3: TLS-only listener using supplied mkcert files. */
Bun.serve({
  port,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: fetchHandler,
});
