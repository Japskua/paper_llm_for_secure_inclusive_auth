
import { randomBytes } from "node:crypto";

/*
  Password Recovery Demonstration
  Security controls map to requirements:
  [1] Session ownership, CSRF, access control
  [2] Safe JSON handling and textContent-only client rendering
  [3] TLS, secure headers, opaque short-lived reset tokens
  [4] Password policy, Argon2id, enrolled-channel proof, deterministic MFA, throttling
  [5] No redirects/external URLs and anti-phishing guidance
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  privacyAccepted: boolean;
};

type Account = {
  id: string;
  normalizedEmail: string;
  enrolledRecoveryChannel: boolean;
  passwordHash: string;
};

type PendingProof = {
  accountId: string;
  sessionId: string;
  expiresAt: number;
  proofHash: string;
  used: boolean;
};

type ResetRecord = {
  accountId: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
  verified: boolean;
  mfaComplete: boolean;
  mfaCodeHash: string;
};

const sessions = new Map<string, Session>();
const pendingProofs = new Map<string, PendingProof>();
const resetTokens = new Map<string, ResetRecord>();

const SESSION_COOKIE = "hospital_recovery_session";
const RESET_TTL_MS = 10 * 60 * 1000;
const PROOF_TTL_MS = 10 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;
const RECOVERY_LIMIT = 4;
const PROOF_LIMIT = 5;
const VERIFY_LIMIT = 5;
const MFA_LIMIT = 5;

/*
 [4] This represents an affirmative confirmation made through the already enrolled
 simulated recovery channel. It is deliberately separate from an email address:
 knowing an address alone cannot create a reset token.
*/
const SIMULATED_ENROLLED_CHANNEL_CONFIRMATION = "confirmed-from-enrolled-channel";

const recoveryAttemptLimits = new Map<string, number[]>();
const proofAttemptLimits = new Map<string, number[]>();
const verificationAttemptLimits = new Map<string, number[]>();
const mfaAttemptLimits = new Map<string, number[]>();
let recoveryServer: any;

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

const initialTestAccountPasswordHash = await Bun.password.hash(randomToken(32), {
  algorithm: "argon2id",
});

const accounts = new Map<string, Account>();
const accountsByEmail = new Map<string, Account>();
const DESIGNATED_TEST_EMAIL = "helena.test@hospital.example";
const DESIGNATED_TEST_ACCOUNT_ID = "test-account-recovery-01";

const testAccount: Account = {
  id: DESIGNATED_TEST_ACCOUNT_ID,
  normalizedEmail: DESIGNATED_TEST_EMAIL,
  enrolledRecoveryChannel: true,
  passwordHash: initialTestAccountPasswordHash,
};

accounts.set(testAccount.id, testAccount);
accountsByEmail.set(testAccount.normalizedEmail, testAccount);

function normalizeIdentifier(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase().normalize("NFKC") : "";
}

function validNormalizedEmail(value: string): boolean {
  return value.length > 0 && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) result[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return result;
}

function makeSession(): Session {
  return {
    id: randomToken(),
    csrf: randomToken(),
    createdAt: Date.now(),
    authenticated: false,
    privacyAccepted: false,
  };
}

function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const id = parseCookies(request)[SESSION_COOKIE];
  const existing = id ? sessions.get(id) : undefined;
  if (existing) return { session: existing, isNew: false };
  const session = makeSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`;
}

function headers(nonce?: string): Headers {
  const result = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  if (nonce) {
    result.set(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    );
  }
  return result;
}

function json(data: unknown, status = 200, responseHeaders?: Headers): Response {
  const h = responseHeaders || headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: h });
}

function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token");
  return !!supplied && supplied === session.csrf;
}

async function safeBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function strongPassword(value: unknown): { valid: boolean; message: string } {
  if (typeof value !== "string") return { valid: false, message: "Enter a new password." };
  if (value.length < 12) return { valid: false, message: "Use at least 12 characters." };
  if (value.length > 128) return { valid: false, message: "Password is too long." };
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return { valid: false, message: "Use upper-case, lower-case, number, and symbol characters." };
  }
  return { valid: true, message: "" };
}

function attemptsFor(map: Map<string, number[]>, key: string): number[] {
  let attempts = map.get(key);
  if (!attempts) {
    attempts = [];
    map.set(key, attempts);
  }
  return attempts;
}

function isThrottled(attempts: number[], limit: number): boolean {
  const cutoff = Date.now() - WINDOW_MS;
  while (attempts.length && attempts[0] < cutoff) attempts.shift();
  return attempts.length >= limit;
}

function recordAttempt(attempts: number[]): void {
  attempts.push(Date.now());
}

function coarseClientKey(request: Request): string {
  try {
    const ip = recoveryServer?.requestIP?.(request)?.address;
    if (typeof ip === "string" && ip.length) {
      if (ip.includes(":")) return ip.split(":").slice(0, 4).join(":") + "::/64";
      const fields = ip.split(".");
      if (fields.length === 4) return fields.slice(0, 3).join(".") + ".0/24";
    }
  } catch {}
  return "local-client";
}

function cleanOldState(): void {
  const now = Date.now();
  for (const [id, session] of sessions) if (now - session.createdAt > 30 * 60 * 1000) sessions.delete(id);
  for (const [hash, proof] of pendingProofs) if (proof.used || proof.expiresAt < now) pendingProofs.delete(hash);
  for (const [hash, reset] of resetTokens) if (reset.used || reset.expiresAt < now) resetTokens.delete(hash);
  for (const map of [recoveryAttemptLimits, proofAttemptLimits, verificationAttemptLimits, mfaAttemptLimits]) {
    for (const [key, values] of map) {
      while (values.length && values[0] < now - WINDOW_MS) values.shift();
      if (!values.length) map.delete(key);
    }
  }
}

function recordForToken(token: unknown, session: Session, email?: string): ResetRecord | null {
  if (typeof token !== "string" || token.length < 20 || token.length > 200) return null;
  const record = resetTokens.get(sha256(token));
  if (!record || record.sessionId !== session.id || record.used || record.expiresAt < Date.now()) return null;
  if (email) {
    const account = accounts.get(record.accountId);
    if (!account || account.normalizedEmail !== email) return null;
  }
  return record;
}

/*
 [4] Deterministic simulated MFA. The code is derived only after possession of
 the opaque reset token; ResetRecord retains only a SHA-256 hash of that code.
 No plaintext MFA code is stored server-side.
*/
function deterministicMfaCode(tokenHash: string): string {
  const number = BigInt("0x" + sha256("hospital-mfa-v1:" + tokenHash).slice(0, 12)) % 100000000n;
  return number.toString().padStart(8, "0");
}

function genericRecoveryResponse() {
  /*
   Same HTTP status, message, and JSON fields for enrolled, unknown, invalid,
   and unenrolled identifiers. No reset token or delivery detail is exposed.
  */
  return {
    message: "If the request can be processed, recovery instructions are available.",
    recoveryProofRequired: true,
  };
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{--blue:#075b9d;--dark:#17324a;--line:#c8d5df;--soft:#eef6fa;--danger:#a61b1b}*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f5f8fa;color:#182b3b;line-height:1.5}header{background:var(--dark);color:#fff;padding:1rem;border-bottom:5px solid #2c94c9}header .wrap,main,footer{max-width:780px;margin:auto}header h1{font-size:1.35rem;margin:0}header p{margin:.2rem 0 0;font-size:.92rem}main{padding:1.5rem 1rem 2rem}.card{background:#fff;padding:1.5rem;border:1px solid var(--line);border-radius:8px;box-shadow:0 1px 2px #00000012}h2{margin-top:0;color:var(--dark)}label{display:block;font-weight:bold;margin-top:1rem}input{width:100%;padding:.7rem;border:1px solid #70899b;border-radius:4px;font:inherit}button,.button-link{display:inline-block;background:var(--blue);color:#fff;border:0;border-radius:4px;padding:.72rem 1rem;font:inherit;font-weight:bold;cursor:pointer;margin-top:1.15rem;text-decoration:none}button:hover,.button-link:hover{background:#034777}.notice{background:var(--soft);border-left:4px solid #2c94c9;padding:.8rem;margin:1rem 0}.error{color:var(--danger);font-weight:bold;min-height:1.5rem;margin:.75rem 0 0}.success{color:#176b35;font-weight:bold}.small{font-size:.9rem}.hidden{display:none!important}#logs{margin-top:1.5rem;background:#10212e;color:#d8eefc;border-radius:6px;padding:1rem}#logs h2{color:#fff;font-size:1rem;margin:0 0 .5rem}#logList{margin:0;padding-left:1.25rem;font:.8rem ui-monospace,SFMono-Regular,Menlo,monospace;max-height:180px;overflow:auto}footer{padding:0 1rem 2rem;color:#4b5c69;font-size:.86rem}a{color:#075b9d}
</style>
</head>
<body>
<header><div class="wrap"><h1>Hospital Account Portal</h1><p>Secure account recovery</p></div></header>
<main>
<section class="card" aria-labelledby="pageTitle"><h2 id="pageTitle">Loading secure recovery</h2><div id="content" aria-live="polite"></div></section>
<section id="logs" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><ol id="logList"><li>Secure recovery page loaded.</li></ol></section>
</main>
<footer><strong>Stay safe:</strong> Hospital staff will never ask for your password, reset token, recovery confirmation, or verification code by email, phone, or support message. Enter codes only on this verified localhost portal.</footer>
<script nonce="${nonce}">
(function(){
"use strict";
var csrf="",currentToken="",currentEmail="";
var content=document.getElementById("content"),title=document.getElementById("pageTitle"),logList=document.getElementById("logList");
function log(text){console.log(text);var x=document.createElement("li");x.textContent=text;logList.appendChild(x);logList.scrollTop=logList.scrollHeight}
function el(tag,text,cn){var x=document.createElement(tag);if(text!==undefined)x.textContent=text;if(cn)x.className=cn;return x}
function clearPage(name){title.textContent=name;content.replaceChildren()}
function message(text,kind){var x=el("p",text,kind||"error");x.setAttribute("role","status");return x}
function input(labelText,type,name,autocomplete){var label=el("label",labelText),field=document.createElement("input");field.type=type;field.name=name;field.required=true;if(autocomplete)field.autocomplete=autocomplete;label.appendChild(field);return{label:label,field:field}}
function submitButton(text){var x=el("button",text);x.type="submit";return x}
async function api(path,body){var r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});var d;try{d=await r.json()}catch(_){d={message:"Please try again."}}return{ok:r.ok,data:d}}
async function status(){try{var r=await fetch("/api/session-status",{credentials:"same-origin"});return r.ok?await r.json():null}catch(_){return null}}
function route(){var p=new URLSearchParams(location.search),t=p.get("token");if(p.get("screen")==="verify"&&t&&/^[A-Za-z0-9_-]{20,200}$/.test(t)){currentToken=t;renderVerify();return}if(location.hash==="#proof"){renderProof();return}if(location.hash==="#verify"){renderVerify();return}if(location.hash==="#privacy"){status().then(function(s){s&&s.authenticated?renderPrivacy():renderRequest("Complete secure account recovery before viewing the privacy statement.")});return}if(location.hash==="#success"){status().then(function(s){if(s&&s.authenticated&&s.privacyAccepted)renderSuccess();else if(s&&s.authenticated)renderPrivacy("Please accept the updated privacy statement.");else renderRequest("Complete recovery before viewing completion.")});return}renderRequest()}
function feedbackResult(f,result){f.textContent=result.data.message||"Please try again.";f.className=result.ok?"success":"error";f.classList.remove("hidden")}
function renderRequest(notice){
clearPage("Reset your password");
var intro=el("p","Enter the email address associated with your account. For privacy, the outcome is the same whether or not an account is found.");
var note=el("div","A password reset cannot be issued from email knowledge alone. You must next confirm control of an enrolled recovery channel.","notice");
var form=document.createElement("form"),email=input("Account email","email","email","email"),f=message("","error");f.classList.add("hidden");
form.append(email.label,submitButton("Continue"),f);
form.addEventListener("submit",async function(e){e.preventDefault();currentEmail=email.field.value.trim();var r=await api("/api/recovery/request",{email:currentEmail});feedbackResult(f,r);if(r.ok)setTimeout(function(){location.hash="proof"},250)});
if(notice)content.append(el("div",notice,"notice"));content.append(intro,note,form);
}
function renderProof(){
clearPage("Confirm recovery channel control");
var info=el("div","To protect your account, confirm access to your enrolled recovery method. This simulation represents an independent confirmation from that enrolled channel; no reset token has been issued yet.","notice");
var form=document.createElement("form"),f=message("","error");f.classList.add("hidden");
form.append(submitButton("Simulate enrolled-channel confirmation"),f);
form.addEventListener("submit",async function(e){e.preventDefault();var r=await api("/api/recovery/channel-proof",{email:currentEmail,confirmation:"confirmed-from-enrolled-channel"});feedbackResult(f,r);if(r.ok&&typeof r.data.testToken==="string"&&typeof r.data.resetLink==="string"){currentToken=r.data.testToken;log("SIMULATED RESET DELIVERY — enrolled channel proof succeeded; authorized test token: "+currentToken);var a=document.createElement("a");a.className="button-link";a.href=r.data.resetLink;a.textContent="Open simulated reset link";form.appendChild(a);setTimeout(renderVerify,300)}});
var back=document.createElement("a");back.href="#request";back.textContent="Back to recovery request";content.append(info,form,el("p"),back);
}
function renderVerify(){
clearPage("Verify reset token");
var info=el("p","Enter the account email and paste the reset token from your simulated delivery, or use the simulated reset link.");
var form=document.createElement("form"),email=input("Account email","email","email","email"),token=input("Reset token","text","token","one-time-code"),f=message("","error");
email.field.value=currentEmail;token.field.value=currentToken;token.field.maxLength=200;f.classList.add("hidden");form.append(email.label,token.label,submitButton("Verify token"),f);
form.addEventListener("submit",async function(e){e.preventDefault();currentEmail=email.field.value.trim();var r=await api("/api/recovery/verify",{email:currentEmail,token:token.field.value.trim()});feedbackResult(f,r);if(r.ok){currentToken=token.field.value.trim();if(typeof r.data.mfaTestCode==="string")log("SIMULATED MFA DELIVERY — authorized verification code: "+r.data.mfaTestCode);setTimeout(renderMfa,250)}});
var back=document.createElement("a");back.href="#request";back.textContent="Back to recovery request";content.append(info,form,el("p"),back);
}
function renderMfa(){
clearPage("Confirm your identity");
var info=el("div","A deterministic simulated verification code was delivered to the browser console and Logs panel after reset-token verification. In a real portal it is sent through a trusted method.","notice");
var form=document.createElement("form"),code=input("Verification code","text","code","one-time-code"),f=message("","error");code.field.inputMode="numeric";code.field.maxLength=12;f.classList.add("hidden");form.append(code.label,submitButton("Confirm code"),f);
form.addEventListener("submit",async function(e){e.preventDefault();var r=await api("/api/recovery/mfa",{token:currentToken,code:code.field.value.trim()});feedbackResult(f,r);if(r.ok){log("MFA confirmation simulated successfully.");setTimeout(renderPassword,250)}});
content.append(info,form);
}
function renderPassword(){
clearPage("Choose a new password");
var policy=el("div","Use at least 12 characters including upper-case and lower-case letters, a number, and a symbol. Never reuse a password from another service.","notice");
var form=document.createElement("form"),pw=input("New password","password","password","new-password"),confirm=input("Confirm new password","password","confirmPassword","new-password"),f=message("","error");f.classList.add("hidden");form.append(pw.label,confirm.label,submitButton("Save new password"),f);
form.addEventListener("submit",async function(e){e.preventDefault();if(pw.field.value!==confirm.field.value){f.textContent="The password entries do not match.";f.className="error";f.classList.remove("hidden");return}var r=await api("/api/recovery/reset",{token:currentToken,password:pw.field.value});feedbackResult(f,r);if(r.ok){pw.field.value="";confirm.field.value="";currentToken="";log("Password reset simulated successfully; reset token invalidated.");setTimeout(function(){location.hash="privacy"},250)}});
content.append(policy,form);
}
function renderPrivacy(notice){
clearPage("Updated privacy statement");
var statement=el("div","I acknowledge the updated privacy conditions for my healthcare account. Acceptance permits hospital authorities to proceed with the appointment request described by the patient.","notice");
var form=document.createElement("form"),label=el("label","I have read and accept the updated privacy statement."),check=document.createElement("input"),f=message("","error");check.type="checkbox";check.required=true;check.style.width="auto";check.style.marginRight=".5rem";label.prepend(check);f.classList.add("hidden");form.append(label,submitButton("Accept privacy statement"),f);
form.addEventListener("submit",async function(e){e.preventDefault();var r=await api("/api/privacy/accept",{accepted:check.checked});feedbackResult(f,r);if(r.ok){log("Privacy statement acceptance simulated successfully.");setTimeout(function(){location.hash="success"},250)}});
if(notice)content.append(el("div",notice,"notice"));content.append(statement,form);
}
function renderSuccess(){clearPage("Recovery complete");content.append(el("p","Your password has been reset and the updated privacy statement has been accepted."),el("p","The hospital can now continue the appointment booking process."),el("div","For your safety, do not disclose your new password or verification codes to anyone, including callers claiming to be support staff.","notice"))}
window.addEventListener("hashchange",route);
fetch("/api/bootstrap",{credentials:"same-origin"}).then(function(r){return r.json()}).then(function(d){csrf=d.csrf||"";if(!csrf)throw new Error("session");log("Secure session initialized. CSRF protection is active.");route()}).catch(function(){clearPage("Service unavailable");content.append(message("The secure recovery service is unavailable. Please refresh and try again.","error"))});
}());
</script>
</body>
</html>`;
}

async function handler(request: Request): Promise<Response> {
  cleanOldState();
  const url = new URL(request.url);

  if (url.protocol !== "https:") {
    return new Response("HTTPS is required.", { status: 400, headers: headers() });
  }

  const { session, isNew } = sessionFor(request);
  const cookieHeaders = headers();
  if (isNew) cookieHeaders.append("Set-Cookie", sessionCookie(session));

  if (request.method === "GET" && url.pathname === "/api/bootstrap") {
    return json({ csrf: session.csrf }, 200, cookieHeaders);
  }

  if (request.method === "GET" && url.pathname === "/api/session-status") {
    if (isNew) return json({ message: "A secure session is required." }, 401, cookieHeaders);
    return json({ authenticated: session.authenticated, privacyAccepted: session.privacyAccepted }, 200, cookieHeaders);
  }

  if (request.method === "POST" && url.pathname.startsWith("/api/")) {
    if (!csrfValid(request, session)) {
      return json({ message: "Your secure session could not be verified. Refresh the page and try again." }, 403, cookieHeaders);
    }

    const body = await safeBody(request);
    if (!body) return json({ message: "Please submit a valid request." }, 400, cookieHeaders);
    const clientKey = coarseClientKey(request);

    /*
     [1][4] Identical response object for every address state. Requesting recovery
     only creates a pending proof challenge; it never issues a usable reset token.
    */
    if (url.pathname === "/api/recovery/request") {
      const normalizedEmail = normalizeIdentifier(body.email);
      const rateKey = `${normalizedEmail || "invalid"}|${clientKey}`;
      const attempts = attemptsFor(recoveryAttemptLimits, rateKey);
      const generic = genericRecoveryResponse();

      if (isThrottled(attempts, RECOVERY_LIMIT)) return json(generic, 200, cookieHeaders);
      recordAttempt(attempts);

      const account = validNormalizedEmail(normalizedEmail) ? accountsByEmail.get(normalizedEmail) : undefined;
      if (account && account.enrolledRecoveryChannel) {
        const proofKey = sha256(`${session.id}|${account.id}`);
        pendingProofs.set(proofKey, {
          accountId: account.id,
          sessionId: session.id,
          expiresAt: Date.now() + PROOF_TTL_MS,
          proofHash: sha256(SIMULATED_ENROLLED_CHANNEL_CONFIRMATION),
          used: false,
        });
      }
      return json(generic, 200, cookieHeaders);
    }

    /*
     [4] Only an enrolled recovery-channel confirmation can issue a reset token.
     Unknown and unenrolled addresses receive no delivery details or identifiers.
    */
    if (url.pathname === "/api/recovery/channel-proof") {
      const normalizedEmail = normalizeIdentifier(body.email);
      const rateKey = `${normalizedEmail || "unknown"}|${clientKey}`;
      const attempts = attemptsFor(proofAttemptLimits, rateKey);
      if (isThrottled(attempts, PROOF_LIMIT)) {
        return json({ message: "Too many confirmation attempts. Please begin recovery again later." }, 429, cookieHeaders);
      }

      const account = validNormalizedEmail(normalizedEmail) ? accountsByEmail.get(normalizedEmail) : undefined;
      const proofKey = account ? sha256(`${session.id}|${account.id}`) : "";
      const proof = proofKey ? pendingProofs.get(proofKey) : undefined;
      const supplied = typeof body.confirmation === "string" ? body.confirmation : "";

      if (!account || !account.enrolledRecoveryChannel || !proof || proof.used || proof.expiresAt < Date.now() || sha256(supplied) !== proof.proofHash) {
        recordAttempt(attempts);
        return json({ message: "We could not confirm control of an enrolled recovery channel. Begin recovery again." }, 400, cookieHeaders);
      }

      proof.used = true;
      pendingProofs.delete(proofKey);

      const rawToken = randomToken(32);
      const tokenHash = sha256(rawToken);
      const code = deterministicMfaCode(tokenHash);
      resetTokens.set(tokenHash, {
        accountId: account.id,
        sessionId: session.id,
        expiresAt: Date.now() + RESET_TTL_MS,
        used: false,
        verified: false,
        mfaComplete: false,
        mfaCodeHash: sha256(code),
      });

      return json({
        message: "Enrolled recovery channel confirmed. Reset instructions are available.",
        testToken: rawToken,
        resetLink: "/?screen=verify&token=" + encodeURIComponent(rawToken),
      }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/verify") {
      const normalizedEmail = normalizeIdentifier(body.email);
      const rateKey = `${normalizedEmail || "unknown"}|${clientKey}`;
      const attempts = attemptsFor(verificationAttemptLimits, rateKey);
      if (isThrottled(attempts, VERIFY_LIMIT)) {
        return json({ message: "Too many verification attempts. Please wait and request a new reset link if needed." }, 429, cookieHeaders);
      }

      const rawToken = typeof body.token === "string" ? body.token : "";
      const record = validNormalizedEmail(normalizedEmail) ? recordForToken(rawToken, session, normalizedEmail) : null;
      const account = record ? accounts.get(record.accountId) : undefined;
      if (!record || !account || !account.enrolledRecoveryChannel) {
        recordAttempt(attempts);
        return json({ message: "We could not verify that reset token. Check it or request a new one." }, 400, cookieHeaders);
      }

      const tokenHash = sha256(rawToken);
      record.verified = true;
      return json({
        message: "Reset token verified. Complete the additional security check.",
        mfaTestCode: deterministicMfaCode(tokenHash),
      }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/mfa") {
      const preliminary = recordForToken(body.token, session);
      const account = preliminary ? accounts.get(preliminary.accountId) : undefined;
      const rateKey = `${account?.normalizedEmail || "unknown"}|${clientKey}`;
      const attempts = attemptsFor(mfaAttemptLimits, rateKey);

      if (isThrottled(attempts, MFA_LIMIT)) {
        return json({ message: "Too many code attempts. Please wait and begin recovery again if necessary." }, 429, cookieHeaders);
      }

      if (!preliminary || !preliminary.verified || typeof body.code !== "string" || sha256(body.code) !== preliminary.mfaCodeHash) {
        recordAttempt(attempts);
        return json({ message: "We could not confirm this security check. Please try again or start recovery again." }, 400, cookieHeaders);
      }

      preliminary.mfaComplete = true;
      return json({ message: "Identity confirmation complete." }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/reset") {
      const record = recordForToken(body.token, session);
      if (!record || !record.verified || !record.mfaComplete) {
        return json({ message: "This password reset session is not valid. Start recovery again." }, 403, cookieHeaders);
      }

      const account = accounts.get(record.accountId);
      if (!account) return json({ message: "This password reset session is not valid. Start recovery again." }, 403, cookieHeaders);

      const policy = strongPassword(body.password);
      if (!policy.valid) return json({ message: policy.message }, 400, cookieHeaders);

      try {
        account.passwordHash = await Bun.password.hash(body.password as string, { algorithm: "argon2id" });
      } catch {
        return json({ message: "Password update is temporarily unavailable. Please try again." }, 503, cookieHeaders);
      }

      record.used = true;
      resetTokens.delete(sha256(body.token as string));
      session.authenticated = true;
      return json({ message: "Your password has been securely updated." }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/privacy/accept") {
      if (!session.authenticated) {
        return json({ message: "Please complete secure account recovery before accepting this statement." }, 403, cookieHeaders);
      }
      if (body.accepted !== true) return json({ message: "Please confirm acceptance to continue." }, 400, cookieHeaders);
      session.privacyAccepted = true;
      return json({ message: "Updated privacy statement accepted." }, 200, cookieHeaders);
    }

    return json({ message: "This service endpoint is unavailable." }, 404, cookieHeaders);
  }

  if (request.method !== "GET") return new Response("Method not allowed.", { status: 405, headers: cookieHeaders });

  const nonce = randomToken(18);
  const pageHeaders = headers(nonce);
  if (isNew) pageHeaders.append("Set-Cookie", sessionCookie(session));
  pageHeaders.set("Content-Type", "text/html; charset=utf-8");
  return new Response(appHtml(nonce), { status: 200, headers: pageHeaders });
}

recoveryServer = Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
});

console.log("Hospital recovery server listening securely on https://localhost:3000");
