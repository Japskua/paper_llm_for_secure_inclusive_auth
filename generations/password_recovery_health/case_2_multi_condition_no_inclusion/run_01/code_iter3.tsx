
type Account = {
  id: string;
  passwordHash: string;
};
type Session = {
  id: string; csrf: string; accountId: string; expiresAt: number;
  resetId?: string; verified: boolean; resetComplete: boolean;
  mfaCodeHash?: string; mfaUsed: boolean; mfaAttempts: number; mfaLockedUntil: number;
  authenticated: boolean; signInAttempts: number; signInLockedUntil: number; privacyAccepted: boolean;
};
type ResetRecord = {
  id: string; tokenHash: string; expiresAt: number; used: boolean;
  sessionId: string; accountId: string; attempts: number; lockedUntil: number;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
/* Task: password state belongs only to opaque internal account records. */
const accounts = new Map<string, Account>();

/* Requirements 1/3: cryptographically random opaque session and reset values. */
function randomToken(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}
function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}
function secretEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function parseCookie(request: Request, name: string): string | undefined {
  const cookies = request.headers.get("cookie") || "";
  for (const part of cookies.split(";")) {
    const at = part.indexOf("=");
    if (at > 0 && part.slice(0, at).trim() === name) {
      const value = part.slice(at + 1).trim();
      if (/^[A-Za-z0-9_-]{20,100}$/.test(value)) return value;
    }
  }
}

/*
 * Task: expiry cleanup runs on every incoming request. A mock recovery context
 * receives an opaque internal account; this identifier is never sent to clients.
 */
function cleanupExpired(now = Date.now()): void {
  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(id);
      for (const [resetId, reset] of resets) {
        if (reset.sessionId === id) resets.delete(resetId);
      }
    }
  }
  for (const [id, reset] of resets) {
    if (reset.expiresAt <= now || !sessions.has(reset.sessionId)) resets.delete(id);
  }
  for (const [accountId] of accounts) {
    let active = false;
    for (const session of sessions.values()) {
      if (session.accountId === accountId) { active = true; break; }
    }
    if (!active) accounts.delete(accountId);
  }
}
function newSession(): Session {
  const account: Account = { id: randomToken(24), passwordHash: "" };
  accounts.set(account.id, account);
  return {
    id: randomToken(), csrf: randomToken(), accountId: account.id,
    /* Task: server-side session expiry is authoritative. */
    expiresAt: Date.now() + 30 * 60_000,
    verified: false, resetComplete: false, mfaUsed: false, mfaAttempts: 0,
    mfaLockedUntil: 0, authenticated: false, signInAttempts: 0,
    signInLockedUntil: 0, privacyAccepted: false,
  };
}
function htmlHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'none'; font-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; upgrade-insecure-requests",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  });
}
function json(data: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^@\s]{1,64}@[A-Za-z0-9.-]{1,189}$/.test(value);
}
function validCode(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 41 || value.length > 141) return false;
  const pieces = value.split(".");
  return pieces.length === 2 &&
    /^[A-Za-z0-9_-]{10,40}$/.test(pieces[0]) &&
    /^[A-Za-z0-9_-]{30,100}$/.test(pieces[1]);
}
function passwordPolicy(password: unknown): string | null {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9\s]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}
/* Task: both reset and session must be bound to precisely the same account. */
function getBoundReset(session: Session): ResetRecord | undefined {
  const record = session.resetId ? resets.get(session.resetId) : undefined;
  return record && record.sessionId === session.id && record.accountId === session.accountId ? record : undefined;
}
function validCsrf(session: Session, body: Record<string, unknown>): boolean {
  return typeof body.csrf === "string" && /^[A-Za-z0-9_-]{30,100}$/.test(body.csrf) && secretEqual(session.csrf, body.csrf);
}
async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  const type = request.headers.get("content-type") || "";
  const length = Number(request.headers.get("content-length") || "0");
  if (!type.startsWith("application/json") || !Number.isFinite(length) || length > 4096) return null;
  try {
    const value = await request.json();
    return value && !Array.isArray(value) && typeof value === "object" ? value as Record<string, unknown> : null;
  } catch { return null; }
}

/* Requirements 1/4: all state-changing API actions require CSRF and live session. */
async function api(request: Request): Promise<Response> {
  const now = Date.now();
  cleanupExpired(now);
  const sessionId = parseCookie(request, "recovery_session");
  const session = sessionId ? sessions.get(sessionId) : undefined;
  const body = await bodyOf(request);
  if (!session || session.expiresAt <= now || !accounts.has(session.accountId) || !body || !validCsrf(session, body)) {
    if (session && session.expiresAt <= now) sessions.delete(session.id);
    return json({ ok: false, message: "Your secure session could not be verified. Refresh and try again." }, 403);
  }
  const account = accounts.get(session.accountId)!;
  const action = body.action;
  if (typeof action !== "string" || !["recover", "verify", "reset", "mfa", "signin", "privacy"].includes(action)) {
    return json({ ok: false, message: "We could not process that request. Please try again." }, 400);
  }

  if (action === "recover") {
    if (!validEmail(body.email)) {
      return json({ ok: true, message: "If an eligible account can be recovered, secure instructions have been prepared." });
    }
    const id = randomToken(16);
    const secret = randomToken(32);
    const code = id + "." + secret;
    resets.set(id, {
      id, tokenHash: sha256(secret), expiresAt: now + 15 * 60_000, used: false,
      sessionId: session.id, accountId: session.accountId, attempts: 0, lockedUntil: 0,
    });
    session.resetId = id;
    session.verified = false;
    session.resetComplete = false;
    session.mfaUsed = false;
    session.authenticated = false;
    session.privacyAccepted = false;
    return json({
      ok: true,
      message: "If an eligible account can be recovered, secure instructions have been prepared.",
      mockCode: code,
    });
  }

  if (action === "verify") {
    if (!validCode(body.code)) return json({ ok: false, message: "That recovery code is invalid or has expired." });
    const [id, secret] = body.code.split(".");
    const record = resets.get(id);
    if (!record || record.sessionId !== session.id || record.accountId !== session.accountId) {
      return json({ ok: false, message: "That recovery code is invalid or has expired." });
    }
    if (record.lockedUntil > now) return json({ ok: false, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    if (record.used) return json({ ok: false, message: "This recovery code has already been used." });
    if (record.expiresAt <= now) {
      resets.delete(record.id);
      return json({ ok: false, message: "This recovery code has expired. Request a new one." });
    }
    if (!secretEqual(record.tokenHash, sha256(secret))) {
      record.attempts++;
      if (record.attempts >= 5) { record.attempts = 0; record.lockedUntil = now + 60_000; }
      return json({ ok: false, message: "That recovery code is invalid or has expired." });
    }
    session.resetId = record.id;
    session.verified = true;
    return json({ ok: true, message: "Recovery code verified. Choose a new password." });
  }

  if (action === "reset") {
    const record = getBoundReset(session);
    if (!record || !session.verified || record.used || record.expiresAt <= now || record.accountId !== account.id) {
      return json({ ok: false, message: "Your recovery step is no longer valid. Start again." }, 403);
    }
    const problem = passwordPolicy(body.password);
    if (problem) return json({ ok: false, message: problem });
    if (typeof body.confirm !== "string" || !secretEqual(body.password as string, body.confirm)) {
      return json({ ok: false, message: "The password entries do not match." });
    }
    /* Requirement 4 / Task: mutate only this bound internal account record. */
    account.passwordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 12 });
    record.used = true;
    session.resetComplete = true;
    session.verified = false;
    session.mfaUsed = false;
    session.mfaAttempts = 0;
    const mfaCode = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    session.mfaCodeHash = sha256(mfaCode);
    return json({ ok: true, message: "Password updated. Confirm the additional security code.", mockMfaCode: mfaCode });
  }

  if (action === "mfa") {
    if (!session.resetComplete || !session.mfaCodeHash || session.mfaUsed) {
      return json({ ok: false, message: "Your security-code step is no longer valid. Start recovery again." }, 403);
    }
    if (session.mfaLockedUntil > now) return json({ ok: false, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    if (typeof body.code !== "string" || !/^\d{6}$/.test(body.code) || !secretEqual(session.mfaCodeHash, sha256(body.code))) {
      session.mfaAttempts++;
      if (session.mfaAttempts >= 5) { session.mfaAttempts = 0; session.mfaLockedUntil = now + 60_000; }
      return json({ ok: false, message: "That security code is not valid." });
    }
    session.mfaUsed = true;
    return json({ ok: true, message: "Security code verified. Sign in with your new password." });
  }

  if (action === "signin") {
    /* Task: verify only the password hash of this authenticated session's account. */
    if (!session.resetComplete || !session.mfaUsed || !account.passwordHash) {
      return json({ ok: false, message: "Complete recovery and the security check before signing in." }, 403);
    }
    if (session.signInLockedUntil > now) return json({ ok: false, message: "Too many attempts. Please wait a minute before trying again." }, 429);
    if (typeof body.password !== "string" || body.password.length > 128 || !(await Bun.password.verify(body.password, account.passwordHash))) {
      session.signInAttempts++;
      if (session.signInAttempts >= 5) { session.signInAttempts = 0; session.signInLockedUntil = now + 60_000; }
      return json({ ok: false, message: "Sign-in details could not be verified." });
    }
    session.authenticated = true;
    return json({ ok: true, message: "Signed in securely." });
  }

  if (action === "privacy") {
    if (!session.authenticated || body.accept !== true) return json({ ok: false, message: "Sign in securely before accepting these conditions." }, 403);
    session.privacyAccepted = true;
    return json({ ok: true, message: "Updated privacy conditions accepted." });
  }
  return json({ ok: false, message: "We could not process that request. Please try again." }, 400);
}

/* Requirements 2/5: no user input is interpolated; browser output uses textContent. */
function page(session: Session, nonce: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure account recovery</title>
<style nonce="${nonce}">
:root{--blue:#075d9d;--dark:#17324d;--line:#cbd6df;--soft:#edf5f9}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:#172b3a;font:16px/1.5 system-ui,sans-serif}header{background:var(--dark);color:#fff;padding:1rem}header div,main{max-width:760px;margin:auto}header strong{font-size:1.15rem}main{padding:2rem 1rem 4rem}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.5rem;box-shadow:0 1px 2px #0001}h1{margin-top:0;font-size:1.7rem}h2{font-size:1.2rem}.step{display:none}.step.active{display:block}label{display:block;font-weight:650;margin-top:1rem}input{width:100%;padding:.7rem;border:1px solid #718494;border-radius:5px;font:inherit}input:focus{outline:3px solid #9bd2f5;outline-offset:1px}button{background:var(--blue);color:#fff;border:0;border-radius:5px;padding:.72rem 1rem;font:inherit;font-weight:700;margin-top:1.2rem;cursor:pointer}button:hover{background:#034a80}.notice{background:var(--soft);border-left:4px solid var(--blue);padding:.8rem 1rem;margin:1rem 0}.status{min-height:1.6rem;margin-top:1rem;font-weight:600}.error{color:#9a241c}.success{color:#176535}.small{font-size:.9rem;color:#465966}.test{background:#fff8df;border:1px solid #d9ba66;padding:.8rem;margin-top:1rem}code{overflow-wrap:anywhere}.check{display:flex;gap:.6rem;align-items:flex-start;font-weight:normal}.check input{width:auto;margin-top:.3rem}nav{margin:.8rem 0 1.2rem;font-size:.9rem}nav a{color:var(--blue);margin-right:.8rem}#logs{background:#101b25;color:#d8f2e2;border-radius:6px;min-height:5rem;max-height:12rem;overflow:auto;padding:.8rem;white-space:pre-wrap;font:12px/1.45 ui-monospace,monospace}
</style></head><body>
<header><div><strong>Patient account</strong><span aria-hidden="true"> · </span>Secure recovery</div></header>
<main id="app" data-csrf="${session.csrf}">
<nav aria-label="Recovery progress"><a href="#recover">1. Recovery</a><a href="#verify">2. Verify</a><a href="#reset">3. New password</a><a href="#mfa">4. Security check</a><a href="#signin">5. Sign in</a></nav>
<div class="card">
<section id="recover" class="step active"><h1>Reset your password</h1><p>Enter the email address used for your patient account. For privacy, the result is the same whether or not an account can be recovered.</p><div class="notice"><strong>Stay safe:</strong> Hospital staff and email senders will never ask for your password, recovery code, or security code. Do not share them with anyone.</div><form id="recover-form"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" maxlength="254" required><button>Prepare recovery instructions</button></form><div class="status" id="recover-status" role="status"></div><div class="test" id="recovery-test" hidden><strong>Academic mock delivery</strong><p class="small">The test recovery code was written to the browser console. It is shown here only for this mock.</p><code id="recovery-code"></code><p><a id="recovery-link" href="#verify">Follow secure mock recovery link</a></p></div></section>
<section id="verify" class="step"><h1>Verify recovery code</h1><p>Paste the recovery code from secure mock delivery, or use the mock link.</p><form id="verify-form"><label for="reset-code">Recovery code</label><input id="reset-code" autocomplete="one-time-code" maxlength="141" required><button>Verify code</button></form><div class="status" id="verify-status" role="status"></div></section>
<section id="reset" class="step"><h1>Choose a strong password</h1><p class="notice">Use 12–128 characters, including uppercase and lowercase letters, a number, and a symbol.</p><form id="reset-form"><label for="new-password">New password</label><input id="new-password" type="password" autocomplete="new-password" maxlength="128" required><label for="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autocomplete="new-password" maxlength="128" required><button>Save new password</button></form><div class="status" id="reset-status" role="status"></div><div class="test" id="mfa-test" hidden><strong>Academic mock delivery</strong><p>Security code: <code id="mfa-code"></code></p></div></section>
<section id="mfa" class="step"><h1>Additional security check</h1><p>Enter the six-digit security code. Never share this code with staff or an email sender.</p><form id="mfa-form"><label for="mfa-input">Security code</label><input id="mfa-input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><button>Verify security code</button></form><div class="status" id="mfa-status" role="status"></div></section>
<section id="signin" class="step"><h1>Sign in</h1><p>Use the new password you just created.</p><form id="signin-form"><label for="signin-password">Password</label><input id="signin-password" type="password" autocomplete="current-password" maxlength="128" required><button>Sign in securely</button></form><div class="status" id="signin-status" role="status"></div></section>
<section id="confirmation" class="step"><h1>Updated privacy conditions</h1><p>You are signed in. Review and accept the updated privacy conditions so hospital authorities can continue with appointment administration.</p><form id="privacy-form"><label class="check" for="privacy-check"><input id="privacy-check" type="checkbox" required><span>I have reviewed and accept the updated privacy conditions.</span></label><button>Accept conditions</button></form><div class="status" id="privacy-status" role="status"></div></section>
</div>
<section aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><p class="small">Simulated delivery and verification events are mirrored here. Passwords are never logged.</p><div id="logs" aria-live="polite">Secure recovery page ready.</div></section>
</main>
<script nonce="${nonce}">
(function(){
"use strict";
var csrf=document.getElementById("app").dataset.csrf,logs=document.getElementById("logs");
var allowed=new Set(["recover","verify","reset","mfa","signin","confirmation"]);
var autoVerifiedCode="";
function audit(message){console.log(message);logs.textContent+="\\n"+message;logs.scrollTop=logs.scrollHeight}
function status(id,message,ok){var n=document.getElementById(id);n.textContent=message||"";n.className="status "+(ok?"success":"error")}
function show(view){if(!allowed.has(view))view="recover";document.querySelectorAll(".step").forEach(function(n){n.classList.toggle("active",n.id===view)});if(location.hash.split("?")[0]!=="#"+view)history.replaceState(null,"","#"+view)}
async function send(action,values){try{var r=await fetch("/api/recovery",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.assign({action:action,csrf:csrf},values))});return await r.json()}catch(_){return {ok:false,message:"A secure connection problem occurred. Please try again."}}}
async function verifyCode(code,automatic){var result=await send("verify",{code:code});status("verify-status",result.message,!!result.ok);if(result.ok){audit(automatic?"Recovery link verified the code.":"Recovery code verified.");show("reset")}}
function readRoute(){var hash=location.hash.slice(1),parts=hash.split("?"),view=parts[0];if(!allowed.has(view)){show("recover");return}show(view);if(view==="verify"&&parts[1]){var code=new URLSearchParams(parts[1]).get("code");if(code&&/^[A-Za-z0-9_-]{10,40}\\.[A-Za-z0-9_-]{30,100}$/.test(code)){document.getElementById("reset-code").value=code;if(autoVerifiedCode!==code){autoVerifiedCode=code;verifyCode(code,true)}}}}
document.getElementById("recover-form").addEventListener("submit",async function(e){e.preventDefault();var result=await send("recover",{email:document.getElementById("email").value});status("recover-status",result.message,!!result.ok);if(result.mockCode){audit("MOCK RECOVERY DELIVERY: recovery code "+result.mockCode);document.getElementById("recovery-code").textContent=result.mockCode;document.getElementById("recovery-link").href="#verify?code="+encodeURIComponent(result.mockCode);document.getElementById("recovery-test").hidden=false}});
document.getElementById("verify-form").addEventListener("submit",function(e){e.preventDefault();verifyCode(document.getElementById("reset-code").value,false)});
document.getElementById("reset-form").addEventListener("submit",async function(e){e.preventDefault();var p=document.getElementById("new-password").value,c=document.getElementById("confirm-password").value;if(p!==c){status("reset-status","The password entries do not match.",false);return}var result=await send("reset",{password:p,confirm:c});document.getElementById("new-password").value="";document.getElementById("confirm-password").value="";status("reset-status",result.message,!!result.ok);if(result.mockMfaCode){audit("MOCK MFA DELIVERY: security code "+result.mockMfaCode);document.getElementById("mfa-code").textContent=result.mockMfaCode;document.getElementById("mfa-test").hidden=false;show("mfa")}});
document.getElementById("mfa-form").addEventListener("submit",async function(e){e.preventDefault();var result=await send("mfa",{code:document.getElementById("mfa-input").value});status("mfa-status",result.message,!!result.ok);if(result.ok){audit("MFA verification succeeded.");show("signin")}});
document.getElementById("signin-form").addEventListener("submit",async function(e){e.preventDefault();var input=document.getElementById("signin-password"),result=await send("signin",{password:input.value});input.value="";status("signin-status",result.message,!!result.ok);if(result.ok){audit("Secure sign-in succeeded.");show("confirmation")}});
document.getElementById("privacy-form").addEventListener("submit",async function(e){e.preventDefault();var result=await send("privacy",{accept:document.getElementById("privacy-check").checked});status("privacy-status",result.message,!!result.ok);if(result.ok)audit("Updated privacy conditions accepted.")});
window.addEventListener("hashchange",readRoute);readRoute();
}());
</script></body></html>`;
}

/* Requirement 3: TLS-only server using provided mkcert files. */
Bun.serve({
  port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") {
        return new Response("Secure connection required.", { status: 400, headers: { "Cache-Control": "no-store" } });
      }
      /* Task: remove expired sessions and reset records before any route is served. */
      cleanupExpired();
      if (url.pathname === "/" && request.method === "GET") {
        const existing = parseCookie(request, "recovery_session");
        let state = existing ? sessions.get(existing) : undefined;
        let created = false;
        if (!state || state.expiresAt <= Date.now() || !accounts.has(state.accountId)) {
          if (state) sessions.delete(state.id);
          state = newSession();
          sessions.set(state.id, state);
          created = true;
        }
        const headers = htmlHeaders(randomToken(18));
        if (created) {
          headers.append("Set-Cookie", "recovery_session=" + state.id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800");
        }
        const nonce = headers.get("Content-Security-Policy")!.match(/script-src 'nonce-([^']+)'/)![1];
        return new Response(page(state, nonce), { headers });
      }
      if (url.pathname === "/api/recovery" && request.method === "POST") return await api(request);
      return new Response("Not found.", { status: 404, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    } catch {
      return new Response("Request could not be completed.", { status: 400, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
    }
  },
});
console.log("Secure recovery service listening at https://localhost:3000");
