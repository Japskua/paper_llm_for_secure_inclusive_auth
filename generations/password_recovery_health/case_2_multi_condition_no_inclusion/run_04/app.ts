
import { readFileSync } from "node:fs";

/**
 * Password Recovery System
 * Single-file Bun HTTPS server and vanilla JavaScript SPA.
 */

const HTTPS_PORT = Number(process.env.PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || (HTTPS_PORT === 8080 ? 8081 : 8080));
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const SESSION_COOKIE = "__Host-recovery_session";
const TOKEN_TTL_MS = 10 * 60 * 1000;
const MFA_CODE = "246810"; // Deterministic local evaluation-only MFA challenge.

type Throttle = { attempts: number[]; lockedUntil: number };
type Session = {
  id: string;
  csrf: string;
  throttles: Map<string, Throttle>;
  verifiedToken?: string;
  mfaComplete: boolean;
  authenticated: boolean;
  privacyAccepted: boolean;
  expiresAt: number;
};
type ResetToken = {
  token: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
  passwordUpdated: boolean;
  mfaVerified: boolean;
  throttles: Map<string, Throttle>;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();
let storedPasswordHash = ""; // Requirement 4: only a bcrypt hash is retained, never plaintext.

/* Requirement 3: cryptographically random session IDs, CSRF values, and recovery tokens. */
function randomValue(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Buffer.from(value).toString("base64url");
}

function createSession(): Session {
  const id = randomValue(32);
  const session: Session = {
    id,
    csrf: randomValue(32),
    throttles: new Map(),
    mfaComplete: false,
    authenticated: false,
    privacyAccepted: false,
    expiresAt: Date.now() + 30 * 60 * 1000,
  };
  sessions.set(id, session);
  return session;
}

function parseCookies(header: string | null): Record<string, string> {
  const result: Record<string, string> = {};
  if (!header) return result;
  for (const item of header.split(";")) {
    const separator = item.indexOf("=");
    if (separator > 0) {
      const key = item.slice(0, separator).trim();
      const value = item.slice(separator + 1).trim();
      result[key] = value;
    }
  }
  return result;
}

function sessionFrom(request: Request): Session | undefined {
  const id = parseCookies(request.headers.get("cookie"))[SESSION_COOKIE];
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(id);
    return undefined;
  }
  return session;
}

/* Requirement 4: throttling is per session and, where applicable, per recovery token. */
function throttle(map: Map<string, Throttle>, name: string, limit = 5, periodMs = 60_000, lockMs = 5 * 60_000) {
  const now = Date.now();
  let state = map.get(name);
  if (!state) {
    state = { attempts: [], lockedUntil: 0 };
    map.set(name, state);
  }
  if (state.lockedUntil > now) {
    return { allowed: false, retryAfter: Math.ceil((state.lockedUntil - now) / 1000) };
  }
  state.attempts = state.attempts.filter((time) => time > now - periodMs);
  state.attempts.push(now);
  if (state.attempts.length > limit) {
    state.lockedUntil = now + lockMs;
    state.attempts = [];
    return { allowed: false, retryAfter: Math.ceil(lockMs / 1000) };
  }
  return { allowed: true, retryAfter: 0 };
}

function throttleResponse(retryAfter: number) {
  return json({ message: `Too many attempts. Please wait ${retryAfter} seconds before trying again.` }, 429, {
    "Retry-After": String(retryAfter),
  });
}

function cookieFor(session: Session): string {
  /* Requirement 1/3: Secure, HttpOnly, strict same-site host-only session cookie. */
  return `${SESSION_COOKIE}=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}

function responseHeaders(nonce?: string): Headers {
  /* Requirements 2 and 3: CSP nonce permits only this server's trusted inline application code. */
  const csp = nonce
    ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`
    : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";
  return new Headers({
    "Content-Security-Policy": csp,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0",
  });
}

function json(data: Record<string, unknown>, status = 200, extra?: Record<string, string>): Response {
  const headers = responseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra || {})) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400): Response {
  /* Requirement 3: generic production-safe errors, never stack traces or internals. */
  return json({ message: "The request could not be completed. Please try again." }, status);
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) return false;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" && parsed.host === host;
  } catch {
    return false;
  }
}

/* Requirement 1: all sensitive state changes validate Origin, session, and unique session CSRF token. */
function protectedSession(request: Request): { session?: Session; error?: Response } {
  const session = sessionFrom(request);
  if (!session) return { error: genericError(401) };
  if (!sameOrigin(request)) return { error: genericError(403) };
  const csrf = request.headers.get("x-csrf-token");
  if (!csrf || csrf.length !== session.csrf.length || !crypto.timingSafeEqual(new TextEncoder().encode(csrf), new TextEncoder().encode(session.csrf))) {
    return { error: genericError(403) };
  }
  return { session };
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validPassword(password: unknown): password is string {
  return typeof password === "string"
    && password.length >= 12
    && password.length <= 128
    && /[a-z]/.test(password)
    && /[A-Z]/.test(password)
    && /\d/.test(password)
    && /[^A-Za-z0-9]/.test(password);
}

function findOwnedToken(session: Session): ResetToken | undefined {
  if (!session.verifiedToken) return undefined;
  const token = resetTokens.get(session.verifiedToken);
  if (!token || token.sessionId !== session.id || token.expiresAt < Date.now() || token.used) return undefined;
  return token;
}

async function api(request: Request, pathname: string): Promise<Response> {
  if (request.method !== "POST") return genericError(405);

  /* Bootstrap is intentionally the sole CSRF exception: it creates no account action and only returns a new CSRF token. */
  if (pathname === "/api/session") {
    if (!sameOrigin(request)) return genericError(403);
    let session = sessionFrom(request);
    if (!session) session = createSession();
    const headers = { "Set-Cookie": cookieFor(session) };
    return json({ csrfToken: session.csrf }, 200, headers);
  }

  const secured = protectedSession(request);
  if (secured.error || !secured.session) return secured.error!;
  const session = secured.session;
  const payload = await body(request);
  if (!payload) return genericError(400);

  if (pathname === "/api/reset-request") {
    const gate = throttle(session.throttles, "reset-request", 3);
    if (!gate.allowed) return throttleResponse(gate.retryAfter);

    // Requirement 2: identifier input is accepted only as opaque data; never returned, logged, or used in HTML.
    if (typeof payload.identifier !== "string" || payload.identifier.length < 3 || payload.identifier.length > 160) return genericError(400);

    const tokenValue = randomValue(32);
    const reset: ResetToken = {
      token: tokenValue,
      sessionId: session.id,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      used: false,
      passwordUpdated: false,
      mfaVerified: false,
      throttles: new Map(),
    };
    resetTokens.set(tokenValue, reset);

    /* Requirement 3/5: generic response; testing-only code is handled only by the browser console. */
    return json({
      message: "If the supplied details match an account, recovery instructions are available in this secure browser session.",
      testingRecoveryCode: tokenValue,
    });
  }

  if (pathname === "/api/verify-token") {
    const gate = throttle(session.throttles, "token-verification", 5);
    if (!gate.allowed) return throttleResponse(gate.retryAfter);
    const candidate = typeof payload.token === "string" ? payload.token : "";
    const token = resetTokens.get(candidate);
    if (!token || token.sessionId !== session.id || token.used || token.expiresAt < Date.now()) return genericError(400);
    const tokenGate = throttle(token.throttles, "token-verification", 5);
    if (!tokenGate.allowed) return throttleResponse(tokenGate.retryAfter);
    session.verifiedToken = token.token;
    return json({ message: "Recovery code verified." });
  }

  if (pathname === "/api/password-update") {
    const gate = throttle(session.throttles, "password-update", 5);
    if (!gate.allowed) return throttleResponse(gate.retryAfter);
    const token = findOwnedToken(session);
    if (!token) return genericError(403);
    const tokenGate = throttle(token.throttles, "password-update", 5);
    if (!tokenGate.allowed) return throttleResponse(tokenGate.retryAfter);
    if (!validPassword(payload.password)) {
      return json({ message: "Use 12 or more characters with uppercase, lowercase, a number, and a symbol." }, 400);
    }

    /* Requirement 4: Bun bcrypt hashing; raw password is neither stored nor rendered. */
    storedPasswordHash = await Bun.password.hash(payload.password, { algorithm: "bcrypt", cost: 10 });
    token.used = true; // Requirement 3: cryptographically random recovery token is single-use.
    token.passwordUpdated = true;
    session.authenticated = true;
    return json({ message: "Password updated. A second verification step is required.", testingMfaCode: MFA_CODE });
  }

  if (pathname === "/api/mfa-verify") {
    const gate = throttle(session.throttles, "mfa-verification", 5);
    if (!gate.allowed) return throttleResponse(gate.retryAfter);
    const token = session.verifiedToken ? resetTokens.get(session.verifiedToken) : undefined;
    if (!token || !token.passwordUpdated || token.sessionId !== session.id) return genericError(403);
    const tokenGate = throttle(token.throttles, "mfa-verification", 5);
    if (!tokenGate.allowed) return throttleResponse(tokenGate.retryAfter);
    if (typeof payload.code !== "string" || payload.code !== MFA_CODE) return genericError(400);
    token.mfaVerified = true;
    session.mfaComplete = true;
    return json({ message: "Second verification complete." });
  }

  if (pathname === "/api/privacy-accept") {
    const gate = throttle(session.throttles, "privacy-accept", 5);
    if (!gate.allowed) return throttleResponse(gate.retryAfter);
    if (payload.accepted !== true || !session.authenticated || !session.mfaComplete) return genericError(403);
    session.privacyAccepted = true;
    console.log("[SIMULATION] Privacy conditions accepted after authenticated recovery and MFA.");
    return json({ message: "Privacy conditions accepted." });
  }

  return genericError(404);
}

function page(): Response {
  const nonce = randomValue(18);
  const headers = responseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(html(nonce), { headers });
}

/* Requirements 2 and 5: fixed template has no interpolation of user-controlled values. */
function html(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--blue:#075b9b;--ink:#17324a;--muted:#52697b;--line:#cbd8e1;--bg:#f3f7fa;--good:#096b43;--warn:#7a4500}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font:17px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink)}
header{background:#fff;border-bottom:4px solid var(--blue);padding:1.1rem 1.5rem}header div,main,footer{max-width:760px;margin:auto}h1{font-size:1.35rem;margin:0}header p{margin:.18rem 0 0;color:var(--muted);font-size:.92rem}
main{padding:2rem 1.25rem 1rem}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.5rem;box-shadow:0 2px 10px #16364b12}
h2{margin-top:0;font-size:1.45rem}label{display:block;font-weight:650;margin-top:1rem}input{display:block;width:100%;margin-top:.35rem;padding:.7rem;border:1px solid #8299aa;border-radius:5px;font:inherit}input:focus{outline:3px solid #80bde766;border-color:var(--blue)}
button{margin-top:1.25rem;border:0;border-radius:5px;background:var(--blue);color:#fff;padding:.72rem 1rem;font:inherit;font-weight:700;cursor:pointer}button:hover{background:#034878}.secondary{background:#e6eef3;color:#17324a;margin-left:.5rem}.secondary:hover{background:#d4e1e9}
.notice{padding:.8rem 1rem;background:#eef7fc;border-left:4px solid var(--blue);margin:1rem 0}.error{padding:.8rem 1rem;background:#fff0ef;border-left:4px solid #ae2922;color:#6f1714;margin:1rem 0}.success{padding:.8rem 1rem;background:#edf8f1;border-left:4px solid var(--good);color:#075332;margin:1rem 0}
small,.muted{color:var(--muted)}a{color:#075b9b;font-weight:650}.check{display:flex;gap:.65rem;align-items:flex-start;font-weight:400}.check input{width:auto;margin-top:.35rem}ul{padding-left:1.3rem}footer{padding:1rem 1.25rem 2rem;color:var(--muted);font-size:.9rem}
#logs{margin-top:1.2rem;background:#102331;color:#d8eef8;border-radius:8px;padding:1rem;min-height:5rem;font:13px/1.45 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.log-title{color:#fff;font-weight:700;margin:0 0 .4rem}.hidden{display:none}
</style>
</head>
<body>
<header><div><h1>Secure healthcare account recovery</h1><p>Protected recovery service • Verify the address before entering a password</p></div></header>
<main>
<section id="app" aria-live="polite"><p>Preparing secure recovery…</p></section>
<section aria-labelledby="log-heading"><h2 class="log-title" id="log-heading">Logs (local testing simulation)</h2><div id="logs">Recovery service starting…</div></section>
</main>
<footer>For your safety, this service never asks for a password or recovery code by email or telephone.</footer>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf = "";
const app = document.getElementById("app");
const logs = document.getElementById("logs");
function log(message){ console.log(message); logs.textContent += "\\n" + message; logs.scrollTop = logs.scrollHeight; }
function message(text, kind){ const p=document.createElement("p"); p.className=kind; p.textContent=text; return p; }
function button(text, secondary){ const b=document.createElement("button"); b.type="submit"; b.textContent=text; if(secondary)b.className="secondary"; return b; }
function link(text, hash){ const a=document.createElement("a"); a.href=hash; a.textContent=text; return a; }
function clear(){ app.replaceChildren(); }
function setScreen(name){ history.replaceState(null,"","#"+name); render(); }
async function api(path, data){
  const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});
  let result={message:"The request could not be completed."};
  try{result=await response.json();}catch{}
  if(!response.ok){const err=new Error(result.message||"The request could not be completed."); err.status=response.status; throw err;}
  return result;
}
function showRequest(){
  clear(); const card=document.createElement("section");card.className="card";
  const h=document.createElement("h2");h.textContent="Reset your password";card.append(h);
  card.append(message("Enter your account contact detail. We provide the same response whether or not it matches an account.","notice"));
  const form=document.createElement("form"); const label=document.createElement("label");label.htmlFor="identifier";label.textContent="Email address or account contact detail";
  const input=document.createElement("input");input.id="identifier";input.name="identifier";input.type="text";input.required=true;input.minLength=3;input.maxLength=160;input.autocomplete="username";
  form.append(label,input,button("Request recovery code")); form.addEventListener("submit",async(e)=>{e.preventDefault(); removeError(form); try{
    const result=await api("/api/reset-request",{identifier:input.value});
    log("[TEST ONLY] Simulated recovery delivery. Code: "+result.testingRecoveryCode);
    log("[TEST ONLY] Simulated secure link: "+location.origin+"/#verify?token="+result.testingRecoveryCode);
    setScreen("verify");
  }catch(err){form.prepend(message(err.message,"error"));}});
  card.append(form);card.append(document.createElement("p")).append(link("Safe authentication guidance","#guidance"));app.append(card);
}
function removeError(node){node.querySelectorAll(".error").forEach(x=>x.remove());}
function showVerify(){
  clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Verify recovery code";card.append(h);
  card.append(message("Open only recovery links you requested. You may also enter the testing recovery code manually.","notice"));
  const form=document.createElement("form");const label=document.createElement("label");label.htmlFor="token";label.textContent="Recovery code";
  const input=document.createElement("input");input.id="token";input.type="text";input.required=true;input.minLength=20;input.maxLength=100;input.autocomplete="one-time-code";form.append(label,input,button("Verify code"));
  form.addEventListener("submit",async(e)=>{e.preventDefault();removeError(form);try{await api("/api/verify-token",{token:input.value.trim()});input.value="";setScreen("password");}catch(err){form.prepend(message(err.message,"error"));}});
  card.append(form);const p=document.createElement("p");p.append(link("Request a new code","#request"));card.append(p);app.append(card);
  const match=location.hash.match(/[?&]token=([^&]+)/);if(match){try{input.value=decodeURIComponent(match[1]);log("[TEST ONLY] Recovery link token detected locally; verifying it requires your action.");}catch{}}
}
function showPassword(){
  clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Create a strong password";card.append(h);
  card.append(message("Use at least 12 characters including uppercase, lowercase, a number, and a symbol. Do not reuse a password from another service.","notice"));
  const form=document.createElement("form");const label=document.createElement("label");label.htmlFor="password";label.textContent="New password";
  const input=document.createElement("input");input.id="password";input.type="password";input.required=true;input.minLength=12;input.maxLength=128;input.autocomplete="new-password";
  form.append(label,input,button("Save password"));form.addEventListener("submit",async(e)=>{e.preventDefault();removeError(form);try{const r=await api("/api/password-update",{password:input.value});input.value="";log("[TEST ONLY] Simulated MFA challenge delivered in this browser. Code: "+r.testingMfaCode);setScreen("mfa");}catch(err){input.value="";form.prepend(message(err.message,"error"));}});
  card.append(form);app.append(card);
}
function showMfa(){
  clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Second verification";card.append(h);
  card.append(message("For this local evaluation, the simulated verification code was delivered to the browser console and Logs panel.","notice"));
  const form=document.createElement("form");const label=document.createElement("label");label.htmlFor="mfa";label.textContent="Verification code";
  const input=document.createElement("input");input.id="mfa";input.type="text";input.required=true;input.inputMode="numeric";input.pattern="[0-9]{6}";input.maxLength=6;input.autocomplete="one-time-code";
  form.append(label,input,button("Verify"));form.addEventListener("submit",async(e)=>{e.preventDefault();removeError(form);try{await api("/api/mfa-verify",{code:input.value});input.value="";setScreen("privacy");}catch(err){form.prepend(message(err.message,"error"));}});
  card.append(form);app.append(card);
}
function showPrivacy(){
  clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Updated privacy conditions";card.append(h);
  const text=document.createElement("p");text.textContent="Please review and accept the updated privacy conditions so authorised hospital staff can continue with the requested appointment process.";card.append(text);
  const form=document.createElement("form");const label=document.createElement("label");label.className="check";const input=document.createElement("input");input.type="checkbox";input.required=true;const span=document.createElement("span");span.textContent="I have read and accept the updated privacy conditions.";label.append(input,span);form.append(label,button("Accept conditions"));
  form.addEventListener("submit",async(e)=>{e.preventDefault();removeError(form);try{await api("/api/privacy-accept",{accepted:input.checked});setScreen("success");}catch(err){form.prepend(message(err.message,"error"));}});
  card.append(form);app.append(card);
}
function showSuccess(){clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Recovery complete";card.append(h);card.append(message("Your password was updated, second verification was completed, and the privacy conditions were accepted.","success"));const p=document.createElement("p");p.append(link("Read safe authentication guidance","#guidance"));card.append(p);app.append(card);}
function showGuidance(){clear();const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Safe authentication guidance";card.append(h);const ul=document.createElement("ul");["Check that the browser address begins with https://localhost before entering credentials.","Never share a password, recovery code, or MFA code by email, text message, or telephone.","Only use a recovery link you requested yourself; do not follow unexpected links.","Contact the hospital through a known official number if a message seems suspicious."].forEach(t=>{const li=document.createElement("li");li.textContent=t;ul.append(li)});card.append(ul);const p=document.createElement("p");p.append(link("Return to password recovery","#request"));card.append(p);app.append(card);}
function render(){const state=location.hash.split("?")[0].replace("#","");({"verify":showVerify,"password":showPassword,"mfa":showMfa,"privacy":showPrivacy,"success":showSuccess,"guidance":showGuidance,"request":showRequest}[state]||showRequest)();}
window.addEventListener("hashchange",render);
(async()=>{try{const r=await fetch("/api/session",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:"{}"});const d=await r.json();if(!r.ok)throw new Error();csrf=d.csrfToken;log("[SIMULATION] Secure local recovery session initialized.");render();}catch{clear();app.append(message("Secure recovery could not be started. Please use the official HTTPS address.","error"));}})();
})();
</script>
</body></html>`;
}

/* Requirement 3: only TLS serves the application; plaintext listener only redirects to a fixed local HTTPS origin. */
function safeRedirectHost(host: string | null): string {
  const bare = (host || "").replace(/:\d+$/, "").toLowerCase();
  return bare === "localhost" || bare === "127.0.0.1" || bare === "[::1]" ? bare : "localhost";
}

const cert = readFileSync(CERT_PATH, "utf8");
const key = readFileSync(KEY_PATH, "utf8");

Bun.serve({
  port: HTTPS_PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page();
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return genericError(404);
    } catch {
      return genericError(500);
    }
  },
});

Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const url = new URL(request.url);
    const host = safeRedirectHost(request.headers.get("host"));
    const targetHost = HTTPS_PORT === 443 ? host : `${host}:${HTTPS_PORT}`;
    return new Response(null, {
      status: 308,
      headers: {
        Location: `https://${targetHost}${url.pathname}${url.search}`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});

console.log(`[SIMULATION] HTTPS recovery service listening on https://localhost:${HTTPS_PORT}`);
console.log(`[SIMULATION] HTTP requests redirect on http://localhost:${HTTP_PORT}`);
