
import { existsSync } from "node:fs";

/*
 * Password Recovery System — single-file Bun HTTPS server and vanilla JS SPA.
 * Security mapping: 1 CSRF/session access control; 2 escaped DOM output;
 * 3 TLS/security headers/short-lived tokens; 4 hashing/throttling/MFA;
 * 5 no external URLs and anti-phishing guidance.
 */

const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3001);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3000);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
const RESET_TOKEN_LIFETIME_MS = 15 * 60 * 1000;
const VERIFIED_FLOW_LIFETIME_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_BLOCK_MS = 10 * 60 * 1000;
const VERIFY_LIMIT = 5;
const RECOVERY_IP_LIMIT = 8;
const MAX_RATE_LIMIT_KEYS = 5000;

/*
 * Task: JSON is deliberately small and read with a bounded stream parser.
 * Field limits are independently enforced server-side before comparison,
 * regular-expression processing, or password hashing.
 */
const MAX_JSON_BODY_BYTES = 2048;
const MAX_EMAIL_LENGTH = 254;
const MAX_TOKEN_LENGTH = 128;
const MAX_PASSWORD_LENGTH = 256;
const MAX_CONFIRMATION_LENGTH = 256;
const MAX_MFA_CODE_LENGTH = 6;

/* Conservative ASCII email format: no display names, comments, quoted locals, or IP literals. */
const CONSERVATIVE_EMAIL =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryRequests: number[];
  flowId: string | null;
  verifiedFlowExpiresAt: number | null;
  resetComplete: boolean;
  mfaFailures: number;
  authenticated: boolean;
  privacyAccepted: boolean;
};

type RecoveryRecord = {
  token: string;
  flowId: string;
  expiresAt: number;
  used: boolean;
  failedAttempts: number;
  blockedUntil: number;
};

type RateLimitRecord = {
  attempts: number[];
  blockedUntil: number;
  lastSeen: number;
};

type ParsedRequest =
  | { body: Record<string, unknown> }
  | { error: "format" | "too-large" };

const sessions = new Map<string, Session>();
const recoveries = new Map<string, RecoveryRecord>();
const verificationRateLimits = new Map<string, RateLimitRecord>();
const recoveryIpRateLimits = new Map<string, RateLimitRecord>();
let secureServer: any = null;
let passwordHash = "";
let passwordHashReady: Promise<void> | null = null;

function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") || "";
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index > -1 && part.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(part.slice(index + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

function getSession(request: Request): Session | null {
  const id = cookieValue(request, "hospital_recovery_session");
  if (!id) return null;
  const session = sessions.get(id) || null;
  if (session && Date.now() - session.createdAt > SESSION_LIFETIME_MS) {
    sessions.delete(id);
    return null;
  }
  return session;
}

function makeSession(): Session {
  const session: Session = {
    id: randomValue(),
    csrf: randomValue(),
    createdAt: Date.now(),
    recoveryRequests: [],
    flowId: null,
    verifiedFlowExpiresAt: null,
    resetComplete: false,
    mfaFailures: 0,
    authenticated: false,
    privacyAccepted: false,
  };
  sessions.set(session.id, session);
  return session;
}

function clearRecoveryFlow(session: Session): void {
  session.flowId = null;
  session.verifiedFlowExpiresAt = null;
  session.resetComplete = false;
  session.mfaFailures = 0;
  session.authenticated = false;
  session.privacyAccepted = false;
}

function recoveryFlowExpired(session: Session, now: number): boolean {
  if (session.verifiedFlowExpiresAt !== null && session.verifiedFlowExpiresAt <= now) {
    clearRecoveryFlow(session);
    return true;
  }
  return false;
}

function commonHeaders(nonce = ""): Headers {
  const headers = new Headers();
  // Requirement 3: browser hardening and no caching of recovery data.
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()");
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`,
  );
  return headers;
}

function json(body: Record<string, unknown>, status = 200): Response {
  const headers = commonHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function trimRateLimitMap(map: Map<string, RateLimitRecord>): void {
  while (map.size > MAX_RATE_LIMIT_KEYS) {
    const key = map.keys().next().value;
    if (typeof key !== "string") break;
    map.delete(key);
  }
}

function clientIp(request: Request): string {
  try {
    const address = secureServer?.requestIP(request)?.address;
    if (typeof address === "string" && address.length > 0) return address;
  } catch {
    // Never trust attacker-controlled forwarding headers.
  }
  return "unavailable-peer";
}

function consumeRateLimit(
  map: Map<string, RateLimitRecord>,
  key: string,
  limit: number,
  now: number,
): { blocked: boolean; retryAfterSeconds: number } {
  let entry = map.get(key);
  if (!entry) {
    entry = { attempts: [], blockedUntil: 0, lastSeen: now };
    map.set(key, entry);
    trimRateLimitMap(map);
  }
  entry.lastSeen = now;
  entry.attempts = entry.attempts.filter((time) => now - time < RATE_WINDOW_MS);

  if (entry.blockedUntil > now) {
    return { blocked: true, retryAfterSeconds: Math.ceil((entry.blockedUntil - now) / 1000) };
  }
  if (entry.attempts.length >= limit) {
    entry.attempts = [];
    entry.blockedUntil = now + RATE_BLOCK_MS;
    return { blocked: true, retryAfterSeconds: Math.ceil(RATE_BLOCK_MS / 1000) };
  }
  entry.attempts.push(now);
  return { blocked: false, retryAfterSeconds: 0 };
}

function cleanOldState(): void {
  const now = Date.now();
  for (const [token, record] of recoveries) {
    if (record.expiresAt < now - 60 * 60 * 1000) recoveries.delete(token);
  }
  for (const [id, session] of sessions) {
    if (session.createdAt < now - SESSION_LIFETIME_MS) sessions.delete(id);
    else recoveryFlowExpired(session, now);
  }
  for (const map of [verificationRateLimits, recoveryIpRateLimits]) {
    for (const [key, entry] of map) {
      if (entry.blockedUntil <= now && entry.lastSeen < now - RATE_WINDOW_MS) map.delete(key);
    }
    trimRateLimitMap(map);
  }
}

// Requirement 1: every sensitive POST is session-bound, CSRF-protected, and origin-checked.
function authorizeStateChange(request: Request): { session: Session } | { error: Response } {
  const session = getSession(request);
  if (!session) return { error: json({ error: "Your secure session has expired. Please reload the page." }, 401) };

  const csrf = request.headers.get("x-csrf-token") || "";
  if (!csrf || csrf !== session.csrf) {
    return { error: json({ error: "This request could not be verified. Please reload and try again." }, 403) };
  }

  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) {
    return { error: json({ error: "This request could not be verified. Please reload and try again." }, 403) };
  }
  return { session };
}

/*
 * Task: Reject declared oversize bodies before reading and enforce the same
 * limit while streaming, before UTF-8 decoding or JSON.parse.
 */
async function requestData(request: Request): Promise<ParsedRequest> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return { error: "format" };

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_JSON_BODY_BYTES) {
      return { error: "too-large" };
    }
  }

  if (!request.body) return { error: "format" };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;

  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_JSON_BODY_BYTES) {
        await reader.cancel();
        return { error: "too-large" };
      }
      chunks.push(part.value);
    }
  } catch {
    return { error: "format" };
  }

  const raw = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    raw.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    if (!value || typeof value !== "object" || Array.isArray(value)) return { error: "format" };
    return { body: value as Record<string, unknown> };
  } catch {
    return { error: "format" };
  }
}

function passwordProblem(password: string): string | null {
  if (password.length < 12) return "Use at least 12 characters.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/[0-9]/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include a symbol.";
  return null;
}

const page = (csrf: string, nonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{--navy:#12314a;--blue:#146c94;--pale:#edf6f9;--line:#c9d8df;--danger:#a32638;--ok:#17663d}*{box-sizing:border-box}body{margin:0;background:#f4f7f8;color:#17242c;font-family:Arial,Helvetica,sans-serif;line-height:1.5}header{background:var(--navy);color:#fff;padding:1.2rem 1rem}header div,main{max-width:760px;margin:auto}header h1{margin:0;font-size:1.35rem}header p{margin:.18rem 0 0;color:#d7edf5;font-size:.94rem}main{padding:1.5rem 1rem 3rem}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.4rem;box-shadow:0 1px 3px #12314a12}h2{margin-top:0;color:var(--navy);font-size:1.35rem}h3{font-size:1rem;margin-bottom:.35rem}label{display:block;font-weight:bold;margin:1rem 0 .32rem}input{width:100%;padding:.72rem;border:1px solid #78909c;border-radius:5px;font-size:1rem}input:focus{outline:3px solid #a9d9ea;outline-offset:1px}button{margin-top:1.1rem;padding:.7rem 1rem;font-size:1rem;border:0;border-radius:5px;background:var(--blue);color:#fff;cursor:pointer}button:hover{background:#0d5679}.secondary{background:#e7f0f3;color:#173d50;border:1px solid #9eb8c2;margin-left:.45rem}.notice{background:var(--pale);border-left:4px solid var(--blue);padding:.8rem;margin:1rem 0}.warning{background:#fff7e7;border-left-color:#a66a00}.status{margin:1rem 0;padding:.75rem;border-radius:5px;background:#eef6f0;color:var(--ok)}.error{background:#fff0f1;color:var(--danger)}.hidden{display:none!important}.small{font-size:.9rem;color:#43545c}.actions{display:flex;flex-wrap:wrap;align-items:center}.check{display:flex;gap:.6rem;align-items:flex-start;margin-top:1rem}.check input{width:auto;margin-top:.3rem}#logs{margin-top:1.3rem;background:#10212c;color:#d9f5e6;border-radius:8px;padding:1rem}#logs h2{color:#fff;font-size:1rem;margin:0 0 .4rem}#log-output{margin:0;max-height:180px;overflow:auto;white-space:pre-wrap;font:.82rem ui-monospace,SFMono-Regular,Consolas,monospace}a{color:#075f87}
</style>
</head>
<body>
<header><div><h1>Hospital Account Recovery</h1><p>Secure access for privacy conditions and appointment support</p></div></header>
<main>
<section id="screen-request" class="card" aria-labelledby="request-title">
<h2 id="request-title">Reset your password</h2>
<p>Enter the email address used for your healthcare account. We will provide the same response whether or not it is registered.</p>
<form id="recovery-form" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="email" required maxlength="254">
<div id="request-message" class="status hidden" role="status"></div><div class="actions"><button type="submit">Request reset instructions</button><button type="button" class="secondary" data-route="verify">Enter a reset token</button></div></form>
<aside class="notice warning"><h3>Stay safe</h3><p class="small">Hospital staff will never ask for your password or MFA code by email or phone. Use this page directly and do not follow unexpected authentication links.</p></aside>
</section>
<section id="screen-verify" class="card hidden" aria-labelledby="verify-title"><h2 id="verify-title">Verify reset token</h2><p>Paste the token from your simulated recovery message, or use the simulated link button after making a request.</p><form id="verify-form" novalidate><label for="token">Reset token</label><input id="token" autocomplete="one-time-code" spellcheck="false" maxlength="128" required><div id="verify-message" class="status hidden" role="status"></div><div class="actions"><button type="submit">Verify token</button><button type="button" class="secondary" data-route="request">Back</button></div></form></section>
<section id="screen-reset" class="card hidden" aria-labelledby="reset-title"><h2 id="reset-title">Choose a new password</h2><p class="small">Use 12 or more characters with uppercase, lowercase, number, and symbol.</p><form id="reset-form" novalidate><label for="password">New password</label><input id="password" type="password" autocomplete="new-password" maxlength="256" required><label for="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autocomplete="new-password" maxlength="256" required><div id="reset-message" class="status hidden" role="status"></div><button type="submit">Save password and continue</button></form></section>
<section id="screen-mfa" class="card hidden" aria-labelledby="mfa-title"><h2 id="mfa-title">One-time verification</h2><p>For this secure demonstration, a six-digit verification code was delivered to the visible Logs panel and browser console.</p><form id="mfa-form" novalidate><label for="mfa-code">Verification code</label><input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required><div id="mfa-message" class="status hidden" role="status"></div><button type="submit">Verify and sign in</button></form></section>
<section id="screen-privacy" class="card hidden" aria-labelledby="privacy-title"><h2 id="privacy-title">Updated privacy conditions</h2><p>Please review and accept the updated privacy conditions so hospital authorities can continue appointment support.</p><div class="notice"><p><strong>Privacy summary:</strong> Your healthcare information is used only for care, appointment coordination, and legally required hospital administration. Keep your account credentials private.</p></div><form id="privacy-form"><label class="check" for="privacy-check"><input id="privacy-check" type="checkbox" required><span>I have read and accept the updated privacy conditions.</span></label><div id="privacy-message" class="status hidden" role="status"></div><button type="submit">Accept conditions</button></form></section>
<section id="screen-complete" class="card hidden" aria-labelledby="complete-title"><h2 id="complete-title">Conditions accepted</h2><p>Your password reset and privacy-condition acceptance have been recorded. Hospital appointment support can now continue.</p><button type="button" data-route="request">Return to recovery start</button></section>
<section id="logs" aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><pre id="log-output" aria-live="polite">Secure recovery page ready.</pre></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},routes=["request","verify","reset","mfa","privacy","complete"],logs=document.getElementById("log-output");let deliveredToken="";
const workflow={tokenVerified:false,passwordSaved:false,mfaVerified:false,privacyAccepted:false};
function log(message){console.log(message);logs.textContent+="\\n"+message;logs.scrollTop=logs.scrollHeight}
function message(id,text,error){const e=document.getElementById(id);e.textContent=text;e.classList.remove("hidden");e.classList.toggle("error",!!error)}
function clear(id){const e=document.getElementById(id);e.textContent="";e.classList.add("hidden");e.classList.remove("error")}
function requested(){const r=location.hash.replace(/^#/,"");return routes.includes(r)?r:"request"}
function guard(r){if(r==="reset"&&!workflow.tokenVerified)return"verify";if(r==="mfa"){if(!workflow.tokenVerified)return"verify";if(!workflow.passwordSaved)return"reset"}if(r==="privacy"){if(!workflow.tokenVerified)return"verify";if(!workflow.passwordSaved)return"reset";if(!workflow.mfaVerified)return"mfa"}if(r==="complete"){if(!workflow.tokenVerified)return"verify";if(!workflow.passwordSaved)return"reset";if(!workflow.mfaVerified)return"mfa";if(!workflow.privacyAccepted)return"privacy"}return r}
function render(){const want=requested(),active=guard(want);if(active!==want)history.replaceState(null,"","#"+active);routes.forEach(n=>document.getElementById("screen-"+n).classList.toggle("hidden",n!==active))}
function go(route){if(!routes.includes(route))return;const active=guard(route);location.hash=active;if(location.hash==="#"+active)render()}
async function api(path,body){const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});const data=await response.json().catch(()=>({error:"The secure service returned an invalid response."}));if(!response.ok)throw new Error(typeof data.error==="string"?data.error:"The request could not be completed.");return data}
document.querySelectorAll("[data-route]").forEach(b=>b.addEventListener("click",()=>go(b.getAttribute("data-route"))));addEventListener("hashchange",render);
document.getElementById("recovery-form").addEventListener("submit",async e=>{e.preventDefault();clear("request-message");const email=document.getElementById("email").value.trim();if(!email||!document.getElementById("email").checkValidity()){message("request-message","Enter a valid email address.",true);return}try{const data=await api("/api/recovery",{email});deliveredToken=String(data.mockToken||"");message("request-message",String(data.message||"If an account can be recovered, instructions have been prepared."),false);log("[Mock delivery] Reset token: "+deliveredToken);log("[Mock delivery] Secure simulated link: #verify (token can also be pasted manually)");const old=document.getElementById("use-link-button");if(old)old.remove();const b=document.createElement("button");b.id="use-link-button";b.type="button";b.className="secondary";b.textContent="Use simulated recovery link";b.addEventListener("click",()=>{document.getElementById("token").value=deliveredToken;go("verify")});document.getElementById("recovery-form").appendChild(b)}catch(err){message("request-message",err.message,true)}});
document.getElementById("verify-form").addEventListener("submit",async e=>{e.preventDefault();clear("verify-message");const token=document.getElementById("token").value.trim();if(!/^[a-f0-9]{32,128}$/i.test(token)){message("verify-message","Enter the reset token exactly as provided.",true);return}try{await api("/api/verify",{token});workflow.tokenVerified=true;workflow.passwordSaved=false;workflow.mfaVerified=false;workflow.privacyAccepted=false;message("verify-message","Token verified.",false);go("reset")}catch(err){message("verify-message",err.message,true)}});
document.getElementById("reset-form").addEventListener("submit",async e=>{e.preventDefault();clear("reset-message");const password=document.getElementById("password").value,confirmation=document.getElementById("confirm-password").value;if(password!==confirmation){message("reset-message","The password confirmation does not match.",true);return}try{const data=await api("/api/reset",{password,confirmation});workflow.passwordSaved=true;workflow.mfaVerified=false;workflow.privacyAccepted=false;log("[Mock MFA delivery] Verification code: "+String(data.mockMfaCode||""));go("mfa")}catch(err){message("reset-message",err.message,true)}});
document.getElementById("mfa-form").addEventListener("submit",async e=>{e.preventDefault();clear("mfa-message");const code=document.getElementById("mfa-code").value.trim();if(!/^[0-9]{6}$/.test(code)){message("mfa-message","Enter the six-digit verification code.",true);return}try{await api("/api/mfa",{code});workflow.mfaVerified=true;workflow.privacyAccepted=false;go("privacy")}catch(err){message("mfa-message",err.message,true)}});
document.getElementById("privacy-form").addEventListener("submit",async e=>{e.preventDefault();clear("privacy-message");if(!document.getElementById("privacy-check").checked){message("privacy-message","Please confirm that you accept the conditions.",true);return}try{await api("/api/privacy",{accepted:true});workflow.privacyAccepted=true;go("complete")}catch(err){message("privacy-message",err.message,true)}});
render()})();
</script>
</body></html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  cleanOldState();

  const auth = authorizeStateChange(request);
  if ("error" in auth) return auth.error;
  const session = auth.session;

  const parsed = await requestData(request);
  if ("error" in parsed) {
    return parsed.error === "too-large"
      ? json({ error: "The request is too large." }, 413)
      : json({ error: "The request format was not accepted." }, 400);
  }
  const body = parsed.body;

  if (pathname === "/api/recovery") {
    const email = typeof body.email === "string" ? body.email.trim() : "";

    /*
     * Task: strict server-side length and conservative syntax validation.
     * This response is intentionally not account-specific, preserving the
     * anti-enumeration recovery behavior.
     */
    if (!email || email.length > MAX_EMAIL_LENGTH || !CONSERVATIVE_EMAIL.test(email)) {
      return json({ error: "Enter a valid email address." }, 400);
    }

    const now = Date.now();
    const ipLimit = consumeRateLimit(recoveryIpRateLimits, clientIp(request), RECOVERY_IP_LIMIT, now);
    if (ipLimit.blocked) {
      return json({ error: "Too many recovery requests from this network. Please wait before trying again." }, 429);
    }

    session.recoveryRequests = session.recoveryRequests.filter((time) => now - time < RATE_WINDOW_MS);
    if (session.recoveryRequests.length >= 3) {
      return json({ error: "Too many recovery requests. Please wait before trying again." }, 429);
    }
    session.recoveryRequests.push(now);

    const token = randomValue(32);
    recoveries.set(token, {
      token,
      flowId: randomValue(24),
      expiresAt: now + RESET_TOKEN_LIFETIME_MS,
      used: false,
      failedAttempts: 0,
      blockedUntil: 0,
    });

    return json({
      message: "If an account can be recovered, reset instructions have been prepared.",
      mockToken: token,
    });
  }

  if (pathname === "/api/verify") {
    // Task: reject an oversized token before lookup or regular-expression processing.
    const token = typeof body.token === "string" ? body.token : "";
    if (token.length > MAX_TOKEN_LENGTH) {
      return json({ error: "This reset token is invalid, expired, or unavailable. Request a new one if needed." }, 400);
    }

    const now = Date.now();
    const verifyLimit = consumeRateLimit(verificationRateLimits, clientIp(request), VERIFY_LIMIT, now);
    if (verifyLimit.blocked) {
      return json({ error: "Too many token verification attempts from this network. Please wait before trying again." }, 429);
    }

    const record = recoveries.get(token);
    if (!/^[a-f0-9]{64}$/i.test(token) || !record || record.expiresAt <= now || record.used || record.blockedUntil > now) {
      return json({ error: "This reset token is invalid, expired, or unavailable. Request a new one if needed." }, 400);
    }

    record.failedAttempts = 0;
    record.used = true;
    session.flowId = record.flowId;
    session.verifiedFlowExpiresAt = now + VERIFIED_FLOW_LIFETIME_MS;
    session.resetComplete = false;
    session.mfaFailures = 0;
    session.authenticated = false;
    session.privacyAccepted = false;
    return json({ ok: true });
  }

  if (pathname === "/api/reset") {
    // Task: maximum password values are checked before equality work or Argon2 hashing.
    const password = typeof body.password === "string" ? body.password : "";
    const confirmation = typeof body.confirmation === "string" ? body.confirmation : "";
    if (password.length > MAX_PASSWORD_LENGTH || confirmation.length > MAX_CONFIRMATION_LENGTH) {
      return json({ error: "The password value is too long." }, 400);
    }

    const now = Date.now();
    if (recoveryFlowExpired(session, now)) {
      return json({ error: "Your verified recovery flow has expired. Please request a new recovery link." }, 403);
    }
    if (!session.flowId || !session.verifiedFlowExpiresAt || session.resetComplete) {
      return json({ error: "Verify a valid reset token before choosing a new password." }, 403);
    }
    if (password !== confirmation) return json({ error: "The password confirmation does not match." }, 400);

    const problem = passwordProblem(password);
    if (problem) return json({ error: problem }, 400);

    // Requirement 4: only Argon2id password hashes are retained.
    if (!passwordHashReady) {
      passwordHashReady = Bun.password.hash("initial-placeholder-value", { algorithm: "argon2id" }).then((hash) => {
        passwordHash = hash;
      });
    }
    await passwordHashReady;
    passwordHash = await Bun.password.hash(password, { algorithm: "argon2id" });
    session.resetComplete = true;
    return json({ ok: true, mockMfaCode: "482916" });
  }

  if (pathname === "/api/mfa") {
    // Task: check MFA value length before workflow/MFA comparison processing.
    const code = typeof body.code === "string" ? body.code : "";
    if (code.length > MAX_MFA_CODE_LENGTH) {
      return json({ error: "The verification code is not correct. Please try again." }, 400);
    }

    const now = Date.now();
    if (recoveryFlowExpired(session, now)) {
      return json({ error: "Your verified recovery flow has expired. Please request a new recovery link before one-time verification." }, 403);
    }
    if (!session.flowId || !session.verifiedFlowExpiresAt || !session.resetComplete || session.authenticated) {
      return json({ error: "A verified password reset is required before one-time verification." }, 403);
    }
    if (session.mfaFailures >= 5) {
      clearRecoveryFlow(session);
      return json({ error: "Too many incorrect codes. Please request a new recovery link." }, 429);
    }
    if (code !== "482916") {
      session.mfaFailures++;
      return json({ error: "The verification code is not correct. Please try again." }, 400);
    }

    session.authenticated = true;
    return json({ ok: true });
  }

  if (pathname === "/api/privacy") {
    const now = Date.now();
    if (recoveryFlowExpired(session, now)) {
      return json({ error: "Your verified recovery flow has expired. Please request a new recovery link before accepting conditions." }, 403);
    }
    if (!session.flowId || !session.verifiedFlowExpiresAt || !session.authenticated) {
      return json({ error: "Sign in securely before accepting privacy conditions." }, 403);
    }
    if (body.accepted !== true) return json({ error: "Privacy-condition acceptance is required." }, 400);

    session.privacyAccepted = true;
    return json({ ok: true });
  }

  return json({ error: "Not found." }, 404);
}

async function httpsFetch(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      cleanOldState();
      let session = getSession(request);
      let created = false;
      if (!session) {
        session = makeSession();
        created = true;
      }

      const nonce = randomValue(16);
      const headers = commonHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      if (created) {
        headers.append(
          "Set-Cookie",
          `hospital_recovery_session=${encodeURIComponent(session.id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`,
        );
      }
      return new Response(page(session.csrf, nonce), { status: 200, headers });
    }

    if (request.method === "POST" && [
      "/api/recovery",
      "/api/verify",
      "/api/reset",
      "/api/mfa",
      "/api/privacy",
    ].includes(url.pathname)) {
      return handleApi(request, url.pathname);
    }

    return json({ error: "Not found." }, 404);
  } catch {
    // Requirement 3: never return stack traces or debugging details.
    return json({ error: "The request could not be completed." }, 500);
  }
}

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

// Requirement 3: TLS uses supplied mkcert localhost certificate/key.
secureServer = Bun.serve({
  port: HTTPS_PORT,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) },
  fetch: httpsFetch,
});

// Requirement 3: HTTP serves no application data and redirects only to fixed localhost HTTPS.
Bun.serve({
  port: HTTP_PORT,
  hostname: "0.0.0.0",
  fetch(request) {
    const url = new URL(request.url);
    const headers = commonHeaders();
    headers.set("Location", `https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`);
    return new Response(null, { status: 308, headers });
  },
});

console.log(`Hospital recovery HTTPS server listening at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirect listener active at http://localhost:${HTTP_PORT}`);
