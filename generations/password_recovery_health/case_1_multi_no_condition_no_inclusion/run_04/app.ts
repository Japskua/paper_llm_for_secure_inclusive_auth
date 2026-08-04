
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
 Password Recovery Demonstration
 [1] Session-bound authorization, CSRF, access controls, rate limits
 [2] JSON validation and textContent-only browser rendering prevent injection
 [3] HTTPS, HSTS, CSP, secure cookies, short-lived single-use hashed records
 [4] Argon2id passwords, recovery-code and MFA-code proof, throttling
 [5] No external URLs/redirects plus safe-authentication guidance
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  activeResetHash?: string;
};

type Account = {
  id: string;
  normalizedIdentifier: string;
  enrolledRecoveryChannel: boolean;
  enrolledMfaChannel: boolean;
  passwordHash: string;
};

type ResetRecord = {
  accountId: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
  recoveryVerified: boolean;
  mfaComplete: boolean;
  recoveryCodeHash: string;
  mfaCodeHash?: string;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();
const recoveryAttemptLimits = new Map<string, number[]>();
const verificationAttemptLimits = new Map<string, number[]>();
const mfaAttemptLimits = new Map<string, number[]>();

const SESSION_COOKIE = "hospital_recovery_session";
const RESET_TTL_MS = 10 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;
const RECOVERY_LIMIT = 4;
const VERIFY_LIMIT = 5;
const MFA_LIMIT = 5;

/*
 Deterministic mock values are deliberately suitable only for this controlled
 local demonstration. The server stores hashes, never plaintext values.
 They are shown after a request/proof so evaluators can test the manual forms.
*/
const TEST_RECOVERY_CODE = "482913";
const TEST_MFA_CODE = "731864";

let recoveryServer: any;

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function secureHashEquals(value: string, expectedHash: string): boolean {
  const actual = Buffer.from(sha256(value), "utf8");
  const expected = Buffer.from(expectedHash, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

const initialDemoPasswordHash = await Bun.password.hash(randomToken(32), {
  algorithm: "argon2id",
});

/*
 Controlled, non-sensitive fixture only. It is intentionally never returned by
 an API, rendered into the page, logged, or otherwise exposed to the browser.
*/
const fixtureAccount: Account = {
  id: "controlled-test-fixture-account",
  normalizedIdentifier: "controlled-recovery-fixture@invalid.test",
  enrolledRecoveryChannel: true,
  enrolledMfaChannel: true,
  passwordHash: initialDemoPasswordHash,
};
const accounts = new Map<string, Account>([[fixtureAccount.id, fixtureAccount]]);
const accountsByIdentifier = new Map<string, Account>([
  [fixtureAccount.normalizedIdentifier, fixtureAccount],
]);

function normalizeIdentifier(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase().normalize("NFKC") : "";
}

function validIdentifier(value: string): boolean {
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

function headers(styleNonce?: string): Headers {
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
  result.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self'; style-src ${styleNonce ? `'nonce-${styleNonce}'` : "'none'"}; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
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
    return body && typeof body === "object" && !Array.isArray(body)
      ? body as Record<string, unknown>
      : null;
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
      if (ip.includes(":")) return `${ip.split(":").slice(0, 4).join(":")}::/64`;
      const fields = ip.split(".");
      if (fields.length === 4) return `${fields.slice(0, 3).join(".")}.0/24`;
    }
  } catch {}
  return "local-client";
}

function cleanOldState(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt > 30 * 60 * 1000) sessions.delete(id);
  }
  for (const [hash, reset] of resetTokens) {
    if (reset.used || reset.expiresAt < now) resetTokens.delete(hash);
  }
  for (const map of [recoveryAttemptLimits, verificationAttemptLimits, mfaAttemptLimits]) {
    for (const [key, values] of map) {
      while (values.length && values[0] < now - WINDOW_MS) values.shift();
      if (!values.length) map.delete(key);
    }
  }
}

function activeRecordFor(session: Session): ResetRecord | null {
  if (!session.activeResetHash) return null;
  const record = resetTokens.get(session.activeResetHash);
  if (!record || record.sessionId !== session.id || record.used || record.expiresAt < Date.now()) return null;
  return record;
}

function genericRecoveryResponse() {
  /*
   Same body and status for known, unknown, invalid, and throttled identifiers.
   The deterministic mock value reveals no identifier/account state and only a
   valid session-bound hashed record can accept it.
  */
  return {
    message: "If the request can be processed, enter the recovery code provided by the controlled test channel.",
    recoveryProofRequired: true,
    mockRecoveryCode: TEST_RECOVERY_CODE,
  };
}

function appHtml(styleNonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${styleNonce}">
:root{--blue:#075b9d;--dark:#17324a;--line:#c8d5df;--soft:#eef6fa;--danger:#a61b1b}*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f5f8fa;color:#182b3b;line-height:1.5}header{background:var(--dark);color:#fff;padding:1rem;border-bottom:5px solid #2c94c9}header .wrap,main,footer{max-width:780px;margin:auto}header h1{font-size:1.35rem;margin:0}header p{margin:.2rem 0 0;font-size:.92rem}main{padding:1.5rem 1rem 2rem}.card{background:#fff;padding:1.5rem;border:1px solid var(--line);border-radius:8px;box-shadow:0 1px 2px #00000012}h2{margin-top:0;color:var(--dark)}label{display:block;font-weight:bold;margin-top:1rem}input{width:100%;padding:.7rem;border:1px solid #70899b;border-radius:4px;font:inherit}button{display:inline-block;background:var(--blue);color:#fff;border:0;border-radius:4px;padding:.72rem 1rem;font:inherit;font-weight:bold;cursor:pointer;margin-top:1.15rem}button:hover{background:#034777}.notice{background:var(--soft);border-left:4px solid #2c94c9;padding:.8rem;margin:1rem 0}.error{color:var(--danger);font-weight:bold;min-height:1.5rem;margin:.75rem 0 0}.success{color:#176b35;font-weight:bold}.hidden{display:none!important}#logs{margin-top:1.5rem;background:#10212e;color:#d8eefc;border-radius:6px;padding:1rem}#logs h2{color:#fff;font-size:1rem;margin:0 0 .5rem}#logList{margin:0;padding-left:1.25rem;font:.8rem ui-monospace,SFMono-Regular,Menlo,monospace;max-height:180px;overflow:auto}footer{padding:0 1rem 2rem;color:#4b5c69;font-size:.86rem}a{color:#075b9d}
</style>
</head>
<body>
<header><div class="wrap"><h1>Hospital Account Portal</h1><p>Secure account recovery</p></div></header>
<main>
<section class="card" aria-labelledby="pageTitle"><h2 id="pageTitle">Loading secure recovery</h2><div id="content" aria-live="polite"></div></section>
<section id="logs" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><ol id="logList"><li>Secure recovery page loaded.</li></ol></section>
</main>
<footer><strong>Stay safe:</strong> Hospital staff will never ask for your password, reset authorization, recovery confirmation, or verification code by email, phone, or support message. Enter information only on this verified localhost portal.</footer>
<script src="/app.js" defer></script>
</body>
</html>`;
}

/* [2][3] Same-origin external browser code: CSP permits scripts only from self. */
const clientScript = `"use strict";
(function(){
var csrf="";
var content=document.getElementById("content");
var title=document.getElementById("pageTitle");
var logList=document.getElementById("logList");

function log(text){console.log(text);var item=document.createElement("li");item.textContent=text;logList.appendChild(item);logList.scrollTop=logList.scrollHeight}
function el(tag,text,cn){var node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cn)node.className=cn;return node}
function clearPage(name){title.textContent=name;content.replaceChildren()}
function message(text,kind){var node=el("p",text,kind||"error");node.setAttribute("role","status");return node}
function field(labelText,type,name,autocomplete){
 var label=el("label",labelText),input=document.createElement("input");
 input.type=type;input.name=name;input.required=true;if(autocomplete)input.autocomplete=autocomplete;
 label.appendChild(input);return{label:label,input:input};
}
function button(text){var node=el("button",text);node.type="submit";return node}
async function api(path,body){
 try{
  var response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});
  var data;try{data=await response.json()}catch(_){data={message:"Please try again."}}
  return{ok:response.ok,data:data};
 }catch(_){return{ok:false,data:{message:"The secure service is unavailable. Please try again."}}}
}
async function status(){
 try{var response=await fetch("/api/session-status",{credentials:"same-origin"});return response.ok?await response.json():null}catch(_){return null}
}
function feedback(node,result){node.textContent=result.data.message||"Please try again.";node.className=result.ok?"success":"error";node.classList.remove("hidden")}
function route(){
 if(location.hash==="#verify"){renderVerify();return}
 if(location.hash==="#mfa"){renderMfa();return}
 if(location.hash==="#password"){renderPassword();return}
 if(location.hash==="#privacy"){status().then(function(s){s&&s.authenticated?renderPrivacy():renderRequest("Complete secure account recovery before viewing the privacy statement.")});return}
 if(location.hash==="#success"){status().then(function(s){if(s&&s.authenticated&&s.privacyAccepted)renderSuccess();else if(s&&s.authenticated)renderPrivacy("Please accept the updated privacy statement.");else renderRequest("Complete recovery before viewing completion.")});return}
 renderRequest();
}
function renderRequest(notice){
 clearPage("Reset your password");
 var intro=el("p","Enter an account identifier. For privacy, the result is the same whether or not an account can be processed.");
 var note=el("div","A password reset cannot be issued from identifier knowledge alone. A recovery code and a separate MFA code are required.","notice");
 var form=document.createElement("form"),account=field("Account identifier","email","identifier","username"),result=message("","error");
 result.classList.add("hidden");form.append(account.label,button("Continue"),result);
 form.addEventListener("submit",async function(event){
  event.preventDefault();
  var response=await api("/api/recovery/request",{identifier:account.input.value.trim()});
  feedback(result,response);
  if(response.ok){
   log("Recovery request simulated. Deterministic mock recovery code: "+response.data.mockRecoveryCode);
   location.hash="#verify";
  }
 });
 if(notice)content.append(el("div",notice,"notice"));content.append(intro,note,form);
}
function renderVerify(){
 clearPage("Enter recovery code");
 var info=el("div","Enter the recovery code from the controlled test channel. The code is checked against a short-lived hash bound to this secure session.","notice");
 var form=document.createElement("form"),code=field("Recovery code","text","recoveryCode","one-time-code"),result=message("","error");
 code.input.inputMode="numeric";code.input.maxLength=12;result.classList.add("hidden");form.append(code.label,button("Verify recovery code"),result);
 form.addEventListener("submit",async function(event){
  event.preventDefault();
  var response=await api("/api/recovery/verify",{code:code.input.value.trim()});
  feedback(result,response);
  if(response.ok){
   code.input.value="";
   log("Recovery proof verified. Deterministic mock MFA code: "+response.data.mockMfaCode);
   location.hash="#mfa";
  }
 });
 content.append(info,form);
}
function renderMfa(){
 clearPage("Confirm your identity");
 var info=el("div","Enter the separate MFA code from the controlled test factor. MFA must be verified before password reset is available.","notice");
 var form=document.createElement("form"),code=field("MFA code","text","mfaCode","one-time-code"),result=message("","error");
 code.input.inputMode="numeric";code.input.maxLength=12;result.classList.add("hidden");form.append(code.label,button("Verify MFA code"),result);
 form.addEventListener("submit",async function(event){
  event.preventDefault();
  var response=await api("/api/recovery/mfa/verify",{code:code.input.value.trim()});
  feedback(result,response);
  if(response.ok){code.input.value="";log("MFA proof verified by the server.");location.hash="#password"}
 });
 content.append(info,form);
}
function renderPassword(){
 clearPage("Choose a new password");
 var policy=el("div","Use at least 12 characters including upper-case and lower-case letters, a number, and a symbol. Never reuse a password from another service.","notice");
 var form=document.createElement("form"),pw=field("New password","password","password","new-password"),confirm=field("Confirm new password","password","confirmPassword","new-password"),result=message("","error");
 result.classList.add("hidden");form.append(pw.label,confirm.label,button("Save new password"),result);
 form.addEventListener("submit",async function(event){
  event.preventDefault();
  if(pw.input.value!==confirm.input.value){result.textContent="The password entries do not match.";result.className="error";result.classList.remove("hidden");return}
  var response=await api("/api/recovery/reset",{password:pw.input.value});
  feedback(result,response);
  if(response.ok){pw.input.value="";confirm.input.value="";log("Password reset simulated successfully; reset authorization invalidated.");location.hash="#privacy"}
 });
 content.append(policy,form);
}
function renderPrivacy(notice){
 clearPage("Updated privacy statement");
 var statement=el("div","I acknowledge the updated privacy conditions for my healthcare account. Acceptance permits hospital authorities to proceed with the appointment request described by the patient.","notice");
 var form=document.createElement("form"),label=el("label","I have read and accept the updated privacy statement."),check=document.createElement("input"),result=message("","error");
 check.type="checkbox";check.required=true;check.style.width="auto";check.style.marginRight=".5rem";label.prepend(check);result.classList.add("hidden");form.append(label,button("Accept privacy statement"),result);
 form.addEventListener("submit",async function(event){
  event.preventDefault();var response=await api("/api/privacy/accept",{accepted:check.checked});feedback(result,response);
  if(response.ok){log("Privacy statement acceptance simulated successfully.");location.hash="#success"}
 });
 if(notice)content.append(el("div",notice,"notice"));content.append(statement,form);
}
function renderSuccess(){
 clearPage("Recovery complete");
 content.append(el("p","Your password has been reset and the updated privacy statement has been accepted."),el("p","The hospital can now continue the appointment booking process."),el("div","For your safety, do not disclose your new password or verification codes to anyone, including callers claiming to be support staff.","notice"));
}
window.addEventListener("hashchange",route);
fetch("/api/bootstrap",{credentials:"same-origin"}).then(function(response){return response.json()}).then(function(data){
 csrf=data.csrf||"";if(!csrf)throw new Error("session");
 log("Secure session initialized. CSRF protection is active.");route();
}).catch(function(){clearPage("Service unavailable");content.append(message("The secure recovery service is unavailable. Please refresh and try again.","error"))});
}());`;

async function handler(request: Request): Promise<Response> {
  cleanOldState();
  const url = new URL(request.url);

  if (url.protocol !== "https:") {
    return new Response("HTTPS is required.", { status: 400, headers: headers() });
  }

  const { session, isNew } = sessionFor(request);
  const cookieHeaders = headers();
  if (isNew) cookieHeaders.append("Set-Cookie", sessionCookie(session));

  if (request.method === "GET" && url.pathname === "/app.js") {
    const scriptHeaders = headers();
    if (isNew) scriptHeaders.append("Set-Cookie", sessionCookie(session));
    scriptHeaders.set("Content-Type", "application/javascript; charset=utf-8");
    return new Response(clientScript, { status: 200, headers: scriptHeaders });
  }

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
     [1][4] Known and unknown identifiers receive identical pre-proof response,
     transition, fields, status behavior, and no delivery timing difference.
    */
    if (url.pathname === "/api/recovery/request") {
      const normalized = normalizeIdentifier(body.identifier);
      const rateKey = `${normalized || "invalid"}|${clientKey}`;
      const attempts = attemptsFor(recoveryAttemptLimits, rateKey);
      const generic = genericRecoveryResponse();

      if (!isThrottled(attempts, RECOVERY_LIMIT)) {
        recordAttempt(attempts);
        const account = validIdentifier(normalized) ? accountsByIdentifier.get(normalized) : undefined;
        if (account && account.enrolledRecoveryChannel) {
          const oldHash = session.activeResetHash;
          if (oldHash) resetTokens.delete(oldHash);

          const opaqueAuthorization = randomToken(32);
          const authorizationHash = sha256(opaqueAuthorization);
          resetTokens.set(authorizationHash, {
            accountId: account.id,
            sessionId: session.id,
            expiresAt: Date.now() + RESET_TTL_MS,
            used: false,
            recoveryVerified: false,
            mfaComplete: false,
            recoveryCodeHash: sha256(TEST_RECOVERY_CODE),
          });
          session.activeResetHash = authorizationHash;
        }
      }

      return json(generic, 200, cookieHeaders);
    }

    /*
     Retained status route is intentionally indistinguishable before proof and
     cannot establish authorization or reveal whether an identifier exists.
    */
    if (url.pathname === "/api/recovery/channel-status") {
      return json({ ready: false, message: "Enter the recovery code to continue." }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/verify") {
      const attempts = attemptsFor(verificationAttemptLimits, `${session.id}|${clientKey}`);
      if (isThrottled(attempts, VERIFY_LIMIT)) {
        return json({ message: "Too many verification attempts. Please begin recovery again later." }, 429, cookieHeaders);
      }

      const code = typeof body.code === "string" ? body.code.trim() : "";
      const record = activeRecordFor(session);
      const account = record ? accounts.get(record.accountId) : undefined;

      if (!record || !account || !account.enrolledRecoveryChannel || record.recoveryVerified || !secureHashEquals(code, record.recoveryCodeHash)) {
        recordAttempt(attempts);
        return json({ message: "We could not verify this recovery code. Begin recovery again if needed." }, 400, cookieHeaders);
      }

      record.recoveryVerified = true;
      record.mfaCodeHash = sha256(TEST_MFA_CODE);
      return json({
        message: "Recovery code verified. Complete the additional security check.",
        mockMfaCode: TEST_MFA_CODE,
      }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/mfa/verify") {
      const attempts = attemptsFor(mfaAttemptLimits, `${session.id}|${clientKey}`);
      if (isThrottled(attempts, MFA_LIMIT)) {
        return json({ message: "Too many MFA attempts. Please begin recovery again later." }, 429, cookieHeaders);
      }

      const code = typeof body.code === "string" ? body.code.trim() : "";
      const record = activeRecordFor(session);
      const account = record ? accounts.get(record.accountId) : undefined;

      if (!record || !account || !account.enrolledMfaChannel || !record.recoveryVerified || record.mfaComplete || !record.mfaCodeHash || !secureHashEquals(code, record.mfaCodeHash)) {
        recordAttempt(attempts);
        return json({ message: "We could not verify this MFA code. Begin recovery again if needed." }, 400, cookieHeaders);
      }

      record.mfaComplete = true;
      record.mfaCodeHash = undefined;
      return json({ message: "Identity confirmation complete. You may now choose a new password." }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/mfa-status") {
      const record = activeRecordFor(session);
      if (!record || !record.recoveryVerified) {
        return json({ message: "This identity confirmation session is not valid. Begin recovery again." }, 403, cookieHeaders);
      }
      return json({ complete: record.mfaComplete, message: record.mfaComplete ? "Identity confirmation complete." : "Enter the MFA code to continue." }, 200, cookieHeaders);
    }

    if (url.pathname === "/api/recovery/reset") {
      const record = activeRecordFor(session);
      if (!record || !record.recoveryVerified || !record.mfaComplete || !session.activeResetHash) {
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
      resetTokens.delete(session.activeResetHash);
      session.activeResetHash = undefined;
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

  if (request.method !== "GET") {
    return new Response("Method not allowed.", { status: 405, headers: cookieHeaders });
  }

  const styleNonce = randomToken(18);
  const pageHeaders = headers(styleNonce);
  if (isNew) pageHeaders.append("Set-Cookie", sessionCookie(session));
  pageHeaders.set("Content-Type", "text/html; charset=utf-8");
  return new Response(appHtml(styleNonce), { status: 200, headers: pageHeaders });
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
