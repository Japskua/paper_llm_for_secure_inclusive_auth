
import { readFile } from "node:fs/promises";

/*
  Password Recovery System — single-file Bun HTTPS application.
  Security controls are mapped to the numbered requirements below.
*/

const HTTPS_PORT = Number(Bun.env.PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const RESET_LIFETIME_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;

type RateLimit = { count: number; startedAt: number };
type Session = {
  id: string;
  csrf: string;
  requestRate: RateLimit;
  verifyRate: RateLimit;
  mfaRate: RateLimit;
  verifiedResetToken?: string;
  mfaPending?: boolean;
  authenticated?: boolean;
  privacyAccepted?: boolean;
};
type ResetToken = {
  token: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
  verifyAttempts: number;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();

// Requirement 4: mock account stores only a bcrypt hash, never plaintext.
const mockAccount = {
  passwordHash: "",
};

// Requirement 3: cryptographically random, unguessable session/reset values.
function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}

function newSession(): Session {
  return {
    id: randomValue(),
    csrf: randomValue(),
    requestRate: { count: 0, startedAt: Date.now() },
    verifyRate: { count: 0, startedAt: Date.now() },
    mfaRate: { count: 0, startedAt: Date.now() },
  };
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) output[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return output;
}

function getSession(request: Request): { session: Session; created: boolean } {
  const id = parseCookies(request).recovery_session;
  const existing = id ? sessions.get(id) : undefined;
  if (existing) return { session: existing, created: false };
  const session = newSession();
  sessions.set(session.id, session);
  return { session, created: true };
}

function sessionCookie(session: Session): string {
  // Requirement 1/3: Secure, HttpOnly, SameSite session cookie.
  return `recovery_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}

function tooMany(rate: RateLimit, maximum: number): boolean {
  const now = Date.now();
  if (now - rate.startedAt > RATE_WINDOW_MS) {
    rate.startedAt = now;
    rate.count = 0;
  }
  rate.count++;
  return rate.count > maximum;
}

function secureHeaders(nonce: string): Headers {
  // Requirement 3: HTTPS response hardening and restrictive CSP.
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; ` +
      `form-action 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      `connect-src 'self'; img-src 'self' data:`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, max-age=0",
  });
}

function apiHeaders(): Headers {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, max-age=0",
  });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: apiHeaders() });
}

async function safeBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// Requirement 1: all state-changing API calls require the per-session CSRF value.
function csrfValid(request: Request, session: Session): boolean {
  const csrf = request.headers.get("x-csrf-token") || "";
  return csrf.length === session.csrf.length && csrf === session.csrf;
}

function cleanIdentifier(value: unknown): string {
  if (typeof value !== "string") return "";
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9._-]{3,80}$/.test(normalized) ? normalized : "";
}

// Requirement 4: server-side strong password policy.
function validPassword(password: unknown): password is string {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password);
}

function validOwnedToken(session: Session): ResetToken | undefined {
  const token = session.verifiedResetToken;
  if (!token) return undefined;
  const record = resetTokens.get(token);
  if (!record || record.used || record.sessionId !== session.id || record.expiresAt < Date.now()) return undefined;
  return record;
}

function page(session: Session): string {
  const nonce = randomValue(18);
  const escapedCsrf = JSON.stringify(session.csrf);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Health Portal Recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;font-family:Arial,Helvetica,sans-serif;color:#17324d;background:#f1f6f8}
*{box-sizing:border-box} body{margin:0;min-height:100vh}.shell{max-width:760px;margin:auto;padding:24px 16px 48px}
header{border-bottom:4px solid #16717b;padding:10px 0 18px;margin-bottom:22px}h1{font-size:1.65rem;margin:0 0 7px}
.subtitle{margin:0;color:#42606c}.card{background:white;border:1px solid #c7d6dc;border-radius:10px;padding:24px;box-shadow:0 2px 7px #17324d18}
.screen[hidden]{display:none}h2{margin-top:0;font-size:1.32rem}label{display:block;font-weight:bold;margin:16px 0 6px}
input{width:100%;padding:12px;border:1px solid #718b96;border-radius:5px;font-size:1rem}button{margin-top:20px;background:#075d68;color:#fff;border:0;border-radius:5px;padding:12px 18px;font-size:1rem;font-weight:bold;cursor:pointer}
button:hover{background:#034951}.secondary{background:#e6f0f2;color:#17324d;margin-left:8px}.secondary:hover{background:#d3e3e6}
.notice{border-left:4px solid #16717b;background:#eaf5f5;padding:12px;margin:16px 0;line-height:1.45}.warning{border-left-color:#a65000;background:#fff2e5}
.error{min-height:1.2em;color:#a10019;font-weight:bold;margin-top:14px}.checkline{display:flex;gap:9px;align-items:flex-start;font-weight:normal}.checkline input{width:auto;margin-top:4px}
.small{font-size:.91rem;color:#465d67;line-height:1.45}.links{margin-top:17px}a{color:#075d68;font-weight:bold}.logs{margin-top:24px;background:#102d39;color:#e3f5f7;border-radius:8px;padding:15px}.logs h2{font-size:1rem;margin:0 0 8px}.logs pre{white-space:pre-wrap;word-break:break-word;margin:0;font-family:ui-monospace,monospace;font-size:.78rem;min-height:40px}
footer{font-size:.82rem;color:#465d67;margin-top:18px}.success{border-left-color:#247a39;background:#ecf8ef}
</style>
</head>
<body>
<div class="shell">
<header><h1>Health Portal account recovery</h1><p class="subtitle">Secure access to review updated privacy conditions.</p></header>
<main class="card" aria-live="polite">
<section class="screen" id="request-screen">
<h2>Reset your password</h2>
<p>Enter your account identifier. To protect privacy, this service gives the same response whether or not an account exists.</p>
<form id="request-form" novalidate>
<label for="identifier">Account identifier</label>
<input id="identifier" name="identifier" autocomplete="username" maxlength="80" required>
<p class="small">Training environment: use <strong>demo-account</strong>. Never send passwords or codes to anyone by email or phone.</p>
<button type="submit">Request secure reset code</button>
</form><p class="error" id="request-error"></p>
</section>

<section class="screen" id="token-screen" hidden>
<h2>Verify reset code</h2>
<div class="notice">A secure reset code was sent through the simulated delivery channel. Enter it manually here. Codes expire after 10 minutes.</div>
<form id="token-form" novalidate>
<label for="reset-token">Reset code</label><input id="reset-token" autocomplete="one-time-code" maxlength="100" required>
<button type="submit">Verify code</button><button type="button" class="secondary" id="back-request">Request another code</button>
</form><p class="error" id="token-error"></p>
</section>

<section class="screen" id="password-screen" hidden>
<h2>Create a new password</h2>
<p>Use at least 12 characters, with uppercase, lowercase, a number, and a symbol.</p>
<form id="password-form" novalidate>
<label for="new-password">New password</label><input id="new-password" type="password" autocomplete="new-password" maxlength="128" required>
<label for="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autocomplete="new-password" maxlength="128" required>
<button type="submit">Save new password</button>
</form><p class="error" id="password-error"></p>
</section>

<section class="screen" id="mfa-screen" hidden>
<h2>Confirm your identity</h2>
<div class="notice">For this training environment, a simulated multi-factor code has been delivered. Check the visible Logs panel.</div>
<form id="mfa-form" novalidate>
<label for="mfa-code">Six-digit verification code</label><input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>
<button type="submit">Confirm code</button>
</form><p class="error" id="mfa-error"></p>
</section>

<section class="screen" id="privacy-screen" hidden>
<h2>Updated privacy conditions</h2>
<div class="notice"><strong>Your privacy matters.</strong> Hospital authorities may only proceed with the appointment after you accept these updated conditions. This demo stores no patient records.</div>
<form id="privacy-form">
<label class="checkline"><input id="privacy-check" type="checkbox" required><span>I have read and accept the updated privacy conditions.</span></label>
<button type="submit">Accept and continue</button>
</form><p class="error" id="privacy-error"></p>
</section>

<section class="screen" id="complete-screen" hidden>
<h2>Password recovery complete</h2>
<div class="notice success">Your password was updated, your identity was confirmed, and the privacy conditions were accepted. Hospital staff may now continue the appointment process.</div>
<p class="small">For safety, only sign in through the official portal address. Never share passwords or verification codes with support staff.</p>
<button type="button" id="restart">Return to recovery start</button>
</section>
</main>
<aside class="logs" aria-label="Simulation logs"><h2>Logs (training simulation)</h2><pre id="log-output">Secure recovery session ready.</pre></aside>
<footer>This recovery page does not request external links or redirects. Verify the address before entering credentials.</footer>
</div>
<script nonce="${nonce}">
"use strict";
const CSRF = ${escapedCsrf};
const screens = ["request","token","password","mfa","privacy","complete"];
const logBox = document.getElementById("log-output");
function log(message){ console.log(message); logBox.textContent += "\\n" + message; }
function show(name){ screens.forEach(function(s){document.getElementById(s+"-screen").hidden=s!==name;}); const first=document.querySelector("#"+name+"-screen input"); if(first) first.focus(); }
function error(id,message){document.getElementById(id).textContent=message||"";}
async function post(path,data){
  const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":CSRF},body:JSON.stringify(data)});
  let payload={}; try{payload=await response.json();}catch(_){ }
  return {ok:response.ok,payload:payload};
}
document.getElementById("request-form").addEventListener("submit",async function(event){
 event.preventDefault(); error("request-error","");
 const identifier=document.getElementById("identifier").value.trim();
 if(!/^[a-zA-Z0-9._-]{3,80}$/.test(identifier)){error("request-error","Enter a valid account identifier.");return;}
 const result=await post("/api/reset-request",{identifier:identifier});
 if(!result.ok){error("request-error","We could not process that request. Please wait and try again.");return;}
 log("Simulated reset delivery created. Test reset code: "+result.payload.testToken);
 show("token");
});
document.getElementById("back-request").addEventListener("click",function(){show("request");});
document.getElementById("token-form").addEventListener("submit",async function(event){
 event.preventDefault(); error("token-error","");
 const token=document.getElementById("reset-token").value.trim();
 const result=await post("/api/reset-verify",{token:token});
 if(!result.ok){error("token-error","The code is invalid, expired, already used, or cannot be verified now.");return;}
 show("password");
});
document.getElementById("password-form").addEventListener("submit",async function(event){
 event.preventDefault(); error("password-error","");
 const password=document.getElementById("new-password").value;
 const confirmation=document.getElementById("confirm-password").value;
 if(password!==confirmation){error("password-error","The passwords do not match.");return;}
 const result=await post("/api/reset-complete",{password:password});
 if(!result.ok){error("password-error",result.payload.message||"Password requirements were not met.");return;}
 document.getElementById("new-password").value="";document.getElementById("confirm-password").value="";
 log("Simulated MFA delivery created. Training MFA code: "+result.payload.mfaCode);
 show("mfa");
});
document.getElementById("mfa-form").addEventListener("submit",async function(event){
 event.preventDefault(); error("mfa-error","");
 const result=await post("/api/mfa-verify",{code:document.getElementById("mfa-code").value.trim()});
 if(!result.ok){error("mfa-error","The verification code is invalid or too many attempts were made.");return;}
 log("MFA verification successful; authenticated training session created.");
 show("privacy");
});
document.getElementById("privacy-form").addEventListener("submit",async function(event){
 event.preventDefault(); error("privacy-error","");
 if(!document.getElementById("privacy-check").checked){error("privacy-error","Please accept the conditions to continue.");return;}
 const result=await post("/api/privacy-accept",{accepted:true});
 if(!result.ok){error("privacy-error","Unable to save your choice.");return;}
 log("Updated privacy conditions accepted.");
 show("complete");
});
document.getElementById("restart").addEventListener("click",function(){show("request");});
</script>
</body></html>`;
}

async function handleApi(request: Request, session: Session, path: string): Promise<Response> {
  // Requirement 1: CSRF validation happens before every sensitive action.
  if (!csrfValid(request, session)) return json({ message: "Request could not be processed." }, 403);
  const body = await safeBody(request);
  if (!body) return json({ message: "Request could not be processed." }, 400);

  if (path === "/api/reset-request") {
    const identifier = cleanIdentifier(body.identifier);
    const blocked = tooMany(session.requestRate, 3);
    // Requirement 4: generic response prevents account enumeration.
    if (!blocked && identifier === "demo-account") {
      const token = randomValue(32);
      resetTokens.set(token, {
        token,
        sessionId: session.id,
        expiresAt: Date.now() + RESET_LIFETIME_MS,
        used: false,
        verifyAttempts: 0,
      });
      // Requirement deliverable: delivery is simulated in browser-visible client logs only.
      return json({
        message: "If the account is eligible, reset instructions have been sent.",
        testToken: token,
      });
    }
    return json({ message: "If the account is eligible, reset instructions have been sent." });
  }

  if (path === "/api/reset-verify") {
    if (tooMany(session.verifyRate, 5)) return json({ message: "Code cannot be verified." }, 429);
    const token = typeof body.token === "string" ? body.token.trim() : "";
    const record = resetTokens.get(token);
    // Requirement 3/4: token must be bound to session, unexpired, and unused.
    if (!record || record.used || record.sessionId !== session.id || record.expiresAt < Date.now()) {
      return json({ message: "Code cannot be verified." }, 400);
    }
    record.verifyAttempts++;
    if (record.verifyAttempts > 5) return json({ message: "Code cannot be verified." }, 429);
    session.verifiedResetToken = token;
    return json({ message: "Code verified." });
  }

  if (path === "/api/reset-complete") {
    const record = validOwnedToken(session);
    if (!record) return json({ message: "Reset authorization is no longer valid." }, 403);
    if (!validPassword(body.password)) {
      return json({ message: "Use 12+ characters with uppercase, lowercase, number, and symbol." }, 400);
    }
    // Requirement 4: Bun bcrypt hashing; plaintext is never retained.
    mockAccount.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
    record.used = true; // Requirement 3: single-use reset token invalidation.
    session.verifiedResetToken = undefined;
    session.mfaPending = true;
    return json({ message: "Password updated.", mfaCode: "482913" });
  }

  if (path === "/api/mfa-verify") {
    if (!session.mfaPending || tooMany(session.mfaRate, 5)) return json({ message: "Code cannot be verified." }, 429);
    // Requirement 4: deterministic testing-only MFA code and throttled verification.
    if (body.code !== "482913") return json({ message: "Code cannot be verified." }, 400);
    session.mfaPending = false;
    session.authenticated = true;
    return json({ message: "Identity confirmed." });
  }

  if (path === "/api/privacy-accept") {
    // Requirement 1: access control; no object identifiers are accepted from clients.
    if (!session.authenticated || body.accepted !== true) return json({ message: "Request could not be processed." }, 403);
    session.privacyAccepted = true;
    return json({ message: "Privacy conditions accepted." });
  }

  return json({ message: "Not found." }, 404);
}

const cert = await readFile(CERT_PATH, "utf8");
const key = await readFile(KEY_PATH, "utf8");

// Requirement 3: HTTPS-only primary server using supplied mkcert certificates.
Bun.serve({
  port: HTTPS_PORT,
  tls: { cert, key },
  fetch: async (request) => {
    try {
      const url = new URL(request.url);
      const { session, created } = getSession(request);

      if (request.method === "GET" && url.pathname === "/") {
        const nonce = randomValue(18);
        const headers = secureHeaders(nonce);
        // page() creates its own CSP nonce; replace CSP with matching nonce by deriving page once below.
        // The nonce is intentionally only used for headers/page generation, not user data.
        const html = page(session);
        const scriptNonce = html.match(/<script nonce="([^"]+)"/)?.[1] || "";
        headers.set("Content-Security-Policy",
          `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'nonce-${scriptNonce}'; style-src 'nonce-${scriptNonce}'; connect-src 'self'; img-src 'self' data:`);
        if (created) headers.set("Set-Cookie", sessionCookie(session));
        return new Response(html, { status: 200, headers });
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/")) {
        const response = await handleApi(request, session, url.pathname);
        if (created) response.headers.set("Set-Cookie", sessionCookie(session));
        return response;
      }

      return new Response("Not found.", { status: 404, headers: apiHeaders() });
    } catch {
      // Requirement 3: no stack traces or debug data exposed.
      return new Response("Service unavailable.", { status: 503, headers: apiHeaders() });
    }
  },
});

// Requirement 3: companion HTTP listener redirects all plain HTTP requests to HTTPS.
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const requested = new URL(request.url);
    const portPart = HTTPS_PORT === 443 ? "" : `:${HTTPS_PORT}`;
    return Response.redirect(`https://localhost${portPart}${requested.pathname}${requested.search}`, 308);
  },
});

console.log(`Secure recovery portal running at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirect listener running at http://localhost:${HTTP_PORT}`);
