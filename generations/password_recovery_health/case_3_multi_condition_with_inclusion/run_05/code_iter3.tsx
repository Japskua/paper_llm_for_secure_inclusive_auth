
import { createHash, randomBytes } from "crypto";

// Requirements 3: TLS-only server using the supplied local development certificates.
const PORT = Number(process.env.PORT || 3000);
const CERT_FILE = Bun.file("certs/cert.pem");
const KEY_FILE = Bun.file("certs/key.pem");

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryRequested?: boolean;
  recoveryAccountKey?: string;
  recoveryTokenHash?: string;
  recoveryVerified?: boolean;
  demoDeliveryCode?: string;
  pendingMfa?: boolean;
  mfaAccountKey?: string;
  authenticated?: boolean;
  privacyAccepted?: boolean;
};

type ResetRecord = {
  tokenHash: string;
  accountKey: string;
  expiresAt: number;
  used: boolean;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
const rateWindows = new Map<string, number[]>();

// Requirements 4: clearly synthetic, approved demonstration identifier; it is not patient data.
const DEMO_APPROVED_IDENTIFIER = "helena.demo@hospital.test";
const DEMO_ACCOUNT_KEY = "approved-mock-account";
const MFA_CODE = "246810";
// Stored in seconds for the secure cookie; converted to milliseconds when checking server records.
const SESSION_MAX_AGE = 60 * 60 * 8;
const RESET_LIFETIME = 15 * 60 * 1000;

// Requirements 4: precomputed bcrypt hash; no plaintext initial password is retained in source.
let accountPasswordHash =
  process.env.MOCK_ACCOUNT_PASSWORD_HASH ||
  "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

// Requirements 1/4: only the explicitly synthetic demo identifier is approved in this mock.
const approvedIdentifierHashes = new Set([
  sha256(DEMO_APPROVED_IDENTIFIER),
  ...(process.env.MOCK_APPROVED_IDENTIFIER_HASH ? [process.env.MOCK_APPROVED_IDENTIFIER_HASH] : []),
]);

let server: any;

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const entry of cookie.split(";")) {
    const index = entry.indexOf("=");
    if (index > 0) {
      result[entry.slice(0, index).trim()] = decodeURIComponent(entry.slice(index + 1).trim());
    }
  }
  return result;
}

// Requirements 1/3: expired server-side sessions are removed and can never be resumed by an old cookie.
function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const sid = parseCookies(request).hospital_session;
  if (sid) {
    const existing = sessions.get(sid);
    if (existing) {
      if (Date.now() - existing.createdAt < SESSION_MAX_AGE * 1000) {
        return { session: existing, isNew: false };
      }
      sessions.delete(sid);
    }
  }

  const session: Session = { id: randomToken(32), csrf: randomToken(32), createdAt: Date.now() };
  sessions.set(session.id, session);
  return { session, isNew: true };
}

// Requirements 3: common security-header baseline used by every normal and error response.
function secureHeaders(nonce: string, session?: Session, newSession = false): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  });
  if (newSession && session) {
    headers.append(
      "Set-Cookie",
      `hospital_session=${encodeURIComponent(session.id)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`,
    );
  }
  return headers;
}

function json(
  value: Record<string, unknown>,
  nonce: string,
  session?: Session,
  newSession = false,
  status = 200,
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: secureHeaders(nonce, session, newSession),
  });
}

function genericError(message: string, nonce: string, session: Session, isNew: boolean, status = 400): Response {
  return json({ ok: false, message }, nonce, session, isNew, status);
}

function rateAllowed(key: string, maximum: number, periodMs: number): { allowed: boolean; retry: number } {
  const now = Date.now();
  const recent = (rateWindows.get(key) || []).filter((time) => now - time < periodMs);
  if (recent.length >= maximum) {
    rateWindows.set(key, recent);
    return { allowed: false, retry: Math.max(1, Math.ceil((periodMs - (now - recent[0])) / 1000)) };
  }
  recent.push(now);
  rateWindows.set(key, recent);
  return { allowed: true, retry: 0 };
}

// Requirements 4: limits remain effective across newly-created sessions using stable source + account/action keys.
function stableSource(request: Request): string {
  try {
    return server.requestIP(request)?.address || "unavailable-source";
  } catch {
    return "unavailable-source";
  }
}

function actionAllowed(
  request: Request,
  session: Session,
  action: string,
  accountKey: string,
  maximum: number,
): { allowed: boolean; retry: number } {
  const period = 15 * 60 * 1000;
  const sourceHash = sha256(stableSource(request));
  const sessionLimit = rateAllowed(`${action}:session:${session.id}`, maximum, period);
  const stableLimit = rateAllowed(`${action}:source:${sourceHash}:account:${accountKey}`, maximum, period);
  if (!sessionLimit.allowed) return sessionLimit;
  return stableLimit;
}

function validIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  return normalized.length >= 3 && normalized.length <= 120 && /^[A-Za-z0-9@._+\- ]+$/.test(normalized);
}

function normalizedIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

function approvedAccountFor(value: unknown): string | null {
  if (!validIdentifier(value)) return null;
  return approvedIdentifierHashes.has(sha256(normalizedIdentifier(value))) ? DEMO_ACCOUNT_KEY : null;
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{20,120}$/.test(value);
}

function passwordPolicy(password: unknown): string | null {
  if (typeof password !== "string") return "Please enter a password.";
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 128) return "Please use 128 characters or fewer.";
  if (/\s/.test(password)) return "Please do not use spaces in this password.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Include an uppercase letter, lowercase letter, number, and symbol.";
  }
  return null;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// Requirements 1: CSRF token is per-session and required by every state-changing route.
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length > 0 && supplied === session.csrf;
}

// Requirements 4: recovery always invalidates previous account authority before a new recovery flow begins.
function clearAccountAuthority(session: Session): void {
  session.authenticated = false;
  session.privacyAccepted = false;
  session.pendingMfa = false;
  session.mfaAccountKey = undefined;
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--navy:#12324a;--blue:#176b9d;--pale:#edf6fa;--line:#c8d8e1;--ink:#17232b;--good:#126943;--warn:#8a4a00;--bad:#a22525}
*{box-sizing:border-box}body{margin:0;background:#f6f9fa;color:var(--ink);font:18px/1.5 Arial,Helvetica,sans-serif}
header{background:var(--navy);color:white;padding:1rem 1.4rem}header .brand{font-size:1.25rem;font-weight:700}header p{margin:.15rem 0 0;font-size:.92rem}
main{max-width:1040px;margin:0 auto;padding:1.4rem;display:grid;grid-template-columns:245px minmax(0,1fr);gap:1.4rem}
aside,section,.card{background:white;border:1px solid var(--line);border-radius:10px;padding:1.15rem;box-shadow:0 1px 2px #12253512}
h1{font-size:1.7rem;line-height:1.2;margin:0 0 .6rem}h2{font-size:1.2rem;margin:.2rem 0 .65rem}p{margin:.45rem 0 1rem}.steps{list-style:none;padding:0;margin:.5rem 0}.steps li{padding:.5rem;border-left:5px solid #cedae0;margin:.3rem 0;color:#52636c}.steps li.active{border-color:var(--blue);background:var(--pale);color:var(--ink);font-weight:700}.steps li.done{border-color:var(--good);color:var(--good)}
label{display:block;font-weight:700;margin-top:.85rem}input{display:block;width:100%;max-width:520px;padding:.7rem;border:2px solid #8097a3;border-radius:6px;font-size:1rem;margin-top:.25rem}input:focus,button:focus{outline:3px solid #f1b43b;outline-offset:2px}
button{display:inline-block;margin:.9rem .55rem 0 0;background:var(--blue);color:white;border:0;border-radius:6px;padding:.7rem 1rem;font-size:1rem;font-weight:700;cursor:pointer}.secondary{background:white;color:var(--navy);border:2px solid var(--blue)}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .85rem;margin:.8rem 0}.success{border-color:var(--good);background:#ecf8f1}.warning{border-color:var(--warn);background:#fff6e8}.error{border-color:var(--bad);background:#fff0f0}.small{font-size:.92rem}.help{margin-top:1rem;background:#fff9e9}.logs{margin-top:1rem;background:#10232e;color:#e3f7ff;border-radius:7px;padding:.65rem;max-height:175px;overflow:auto;font:13px/1.4 monospace;white-space:pre-wrap}.muted{color:#52636c}.policy{padding-left:1.2rem}.policy li{margin:.25rem 0}code{background:#e8f0f4;padding:.1rem .3rem;border-radius:3px;overflow-wrap:anywhere}@media(max-width:760px){main{display:block;padding:1rem}aside{margin-bottom:1rem}}
</style>
</head>
<body>
<header><div class="brand">Hospital secure account portal</div><p>Check that the address begins with <strong>https://localhost</strong>. We never ask for a password or code by email or phone.</p></header>
<main>
<aside aria-label="Recovery progress"><h2>Your progress</h2><ol class="steps" id="steps"></ol><button class="secondary" id="pauseButton" type="button">Pause and return later</button><p class="small muted">There is no countdown. Your secure session keeps your place.</p></aside>
<section aria-live="polite">
<div id="content"></div>
<div class="card help"><h2>Help and safe sign-in</h2><p>If anything feels unclear, pause here. You can return without starting over in this browser.</p><p class="small">Only enter your password and one-time code on this hospital page. Hospital staff will never ask you to read a password or recovery code aloud.</p><button class="secondary" id="helpButton" type="button">Show a short reminder</button><div id="helpMessage" class="notice" hidden></div></div>
<h2 class="small">Activity logs for this demonstration</h2><div id="logs" class="logs" aria-label="Demonstration activity logs">Ready. Security events will appear here.</div>
</section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
const content=document.getElementById("content"),stepsNode=document.getElementById("steps"),logs=document.getElementById("logs"),helpMessage=document.getElementById("helpMessage"),pauseButton=document.getElementById("pauseButton");
const demoIdentifier="helena.demo@hospital.test";
let csrf="",rememberedLinkToken=new URLSearchParams(location.search).get("token")||"",screen="start";
const steps=[["start","1. Start"],["verify","2. Check recovery code"],["password","3. Create password"],["mfa","4. Confirm security code"],["privacy","5. Accept privacy conditions"],["confirmation","6. Finished"]];
function log(message){console.log(message);logs.textContent+="\\n"+message;logs.scrollTop=logs.scrollHeight}
function el(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n}
function button(text,className){const n=el("button",text);n.type="button";if(className)n.className=className;return n}
function notice(text,kind){const n=el("div",text);n.className="notice "+(kind||"");return n}
function field(form,labelText,type,name,autocomplete){const l=el("label",labelText),i=document.createElement("input");i.type=type;i.name=name;i.id=name;i.required=true;i.autocomplete=autocomplete||"off";l.htmlFor=name;form.append(l,i);return i}
function showMessage(message,kind){const old=content.querySelector(".response-message");if(old)old.remove();const n=notice(message,kind);n.classList.add("response-message");content.append(n)}
function setSteps(){stepsNode.replaceChildren();const active=Math.max(0,steps.findIndex(x=>x[0]===screen));steps.forEach((x,i)=>{const n=el("li",x[1]);if(i===active)n.className="active";if(i<active)n.className="done";stepsNode.append(n)})}
async function api(path,body){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});const d=await r.json();if(!r.ok&&!d.message)d.message="We could not complete that step. Please try again.";return d}catch{return{ok:false,message:"Connection unavailable. Your progress is still saved; please try again."}}}
pauseButton.addEventListener("click",()=>{localStorage.setItem("hospital-recovery-paused","yes");log("Recovery paused locally. No password or code was saved in the browser.");showMessage("Paused. When you are ready, use Resume recovery below. Your secure server progress remains available.","warning")});
document.getElementById("helpButton").addEventListener("click",()=>{helpMessage.hidden=!helpMessage.hidden;helpMessage.textContent="Short reminder: do one step at a time. Use only this HTTPS hospital page, and never share passwords or one-time codes."});
function title(a,b){content.append(el("h1",a),el("p",b))}
function render(){content.replaceChildren();setSteps();if(screen==="start")start();else if(screen==="verify")verify();else if(screen==="password")password();else if(screen==="mfa")mfa();else if(screen==="privacy")privacy();else confirmation()}
function start(){
title("Reset your password","Step 1 of 6. Enter the account email or account ID you use with the hospital.");
content.append(notice("For privacy, we give the same response whether or not an account can receive a recovery message.",""));
const demo=notice("Approved synthetic demonstration identifier: "+demoIdentifier+". This is test data only, not a patient email or account.","success");const code=el("code",demoIdentifier);demo.replaceChildren("Approved synthetic demonstration identifier: ",code,". This is test data only, not a patient email or account.");content.append(demo);
const f=document.createElement("form"),id=field(f,"Account email or ID","text","identifier","username");id.maxLength=120;const submit=el("button","Send recovery code");submit.type="submit";f.append(submit);
f.addEventListener("submit",async e=>{e.preventDefault();submit.disabled=true;const d=await api("/api/recovery",{identifier:id.value});submit.disabled=false;if(!d.ok)return showMessage(d.message,"error");showMessage(d.message,"success");localStorage.removeItem("hospital-recovery-paused");screen="verify";render()});
content.append(f,el("p","Next: open the simulated delivery message or enter a recovery code manually.","small"));const login=button("I know my password — sign in","secondary");login.addEventListener("click",loginPage);content.append(login)}
function loginPage(){content.replaceChildren();title("Sign in securely","Use this only on the hospital HTTPS page. After sign-in, you will confirm a security code.");content.append(notice("Anti-phishing reminder: never follow a password request from an email. Type the hospital address yourself.","warning"));const f=document.createElement("form"),id=field(f,"Account email or ID","text","identifier","username"),pw=field(f,"Password","password","password","current-password"),s=el("button","Sign in");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const d=await api("/api/login",{identifier:id.value,password:pw.value});pw.value="";s.disabled=false;if(!d.ok)return showMessage(d.message,"error");log("Mock hospital MFA code: "+d.mockMfaCode+". This code is shown only in browser console and activity logs.");screen="mfa";render();showMessage("Password checked. Next, enter the security code.","success")});const reset=button("I need to reset my password","secondary");reset.addEventListener("click",()=>{screen="start";render()});content.append(f,reset)}
function verify(){
title("Check your recovery code","Step 2 of 6. Paste or type the code from the secure hospital recovery message.");
content.append(notice("You may use either the simulated recovery link or this manual code box. Nothing happens until you choose Verify code.",""));
const delivery=button("Open simulated recovery delivery","secondary");delivery.addEventListener("click",async()=>{delivery.disabled=true;const d=await api("/api/demo/recovery-code",{});delivery.disabled=false;if(!d.ok)return showMessage(d.message,"error");rememberedLinkToken=d.mockRecoveryCode||"";log("Mock hospital delivery: recovery code "+rememberedLinkToken+". This demonstration logs the code only in the browser console and activity logs.");showMessage("Simulated delivery opened. The code is ready in the box below.","success");const link=button("Open simulated recovery link","secondary");link.addEventListener("click",()=>location.href=d.recoveryLink);content.append(link)});content.append(delivery);
const f=document.createElement("form"),token=field(f,"Recovery code","text","token","one-time-code");token.maxLength=120;if(rememberedLinkToken){token.value=rememberedLinkToken;content.append(notice("A recovery link opened this page. The code was placed here for you, but it has not been checked yet.","success"))}const s=el("button","Verify code");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const d=await api("/api/verify",{token:token.value});s.disabled=false;if(!d.ok)return showMessage(d.message,"error");rememberedLinkToken="";history.replaceState({},"","/");screen="password";render();showMessage(d.message,"success")});const back=button("Back to recovery request","secondary");back.addEventListener("click",()=>{screen="start";render()});content.append(f,back,el("p","Recovery codes expire after 15 minutes and can only be used once.","small muted"))}
function password(){title("Create a strong password","Step 3 of 6. Choose a new password. We will not show or log it.");const list=el("ul");list.className="policy";["At least 12 characters","An uppercase letter and lowercase letter","A number and a symbol","No spaces"].forEach(x=>list.append(el("li",x)));content.append(el("h2","Password checklist"),list);const f=document.createElement("form"),pw=field(f,"New password","password","password","new-password"),cf=field(f,"Confirm new password","password","confirm","new-password"),s=el("button","Save new password");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const d=await api("/api/password",{password:pw.value,confirm:cf.value});pw.value=cf.value="";s.disabled=false;if(!d.ok)return showMessage(d.message,"error");log("Mock hospital MFA code: "+d.mockMfaCode+". This code is shown only in browser console and activity logs.");screen="mfa";render();showMessage("New password saved securely. Next, confirm your security code.","success")});content.append(f)}
function mfa(){title("Confirm your security code","Step 4 of 6. This extra check protects your account after a password reset or sign-in.");content.append(notice("Enter the one-time code from the secure hospital message. Never share this code with anyone.","warning"));const f=document.createElement("form"),code=field(f,"Security code","text","code","one-time-code");code.inputMode="numeric";code.maxLength=12;const s=el("button","Confirm code");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const d=await api("/api/mfa",{code:code.value});s.disabled=false;code.value="";if(!d.ok)return showMessage(d.message,"error");screen="privacy";render();showMessage(d.message,"success")});content.append(f)}
function privacy(){title("Review updated privacy conditions","Step 5 of 6. You are signed in. Read this short summary, then choose one clear action.");content.append(notice("Your healthcare account information is protected. This page does not display patient identifiers.","success"));const l=el("ul");l.className="policy";["Hospital authorities may use your account confirmation to arrange your requested appointment.","Only authorised hospital staff may access necessary health information.","You can ask the hospital for help with these conditions at any time."].forEach(x=>l.append(el("li",x)));content.append(el("h2","Summary"),l);const a=button("Accept updated privacy conditions");a.addEventListener("click",async()=>{a.disabled=true;const d=await api("/api/privacy/accept",{});a.disabled=false;if(!d.ok)return showMessage(d.message,"error");screen="confirmation";render()});content.append(a)}
function confirmation(){title("You are all set","Step 6 of 6. The updated privacy conditions have been recorded.");content.append(notice("Simulated appointment-booking handoff completed. Hospital staff can now continue with the medication review appointment request.","success"),el("p","You may safely close this page. No patient details are shown here."));const r=button("Return to secure start","secondary");r.addEventListener("click",()=>{screen="start";render()});content.append(r)}
async function bootstrap(){try{const r=await fetch("/api/status",{credentials:"same-origin"}),d=await r.json();csrf=d.csrf||"";if(d.authenticated&&d.privacyAccepted)screen="confirmation";else if(d.authenticated)screen="privacy";else if(d.pendingMfa)screen="mfa";else if(d.recoveryVerified)screen="password";else if(d.recoveryRequested||rememberedLinkToken)screen="verify";else screen="start";if(localStorage.getItem("hospital-recovery-paused")==="yes")log("A paused recovery reminder was found. Resume whenever you feel ready.");render()}catch{content.textContent="Secure connection could not be established. Please refresh this hospital page."}}
bootstrap();
})();
</script>
</body>
</html>`;
}

server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: CERT_FILE, key: KEY_FILE },
  async fetch(request: Request) {
    const url = new URL(request.url);
    const nonce = randomToken(18);
    const { session, isNew } = sessionFor(request);

    if (url.protocol !== "https:") {
      const headers = secureHeaders(nonce, session, isNew);
      headers.set("Content-Type", "text/plain; charset=utf-8");
      return new Response("HTTPS is required.", { status: 400, headers });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery-link")) {
      const headers = secureHeaders(nonce, session, isNew);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(appHtml(nonce), { headers });
    }

    if (request.method === "GET" && url.pathname === "/api/status") {
      return json({
        ok: true,
        csrf: session.csrf,
        recoveryRequested: !!session.recoveryRequested,
        recoveryVerified: !!session.recoveryVerified,
        pendingMfa: !!session.pendingMfa,
        authenticated: !!session.authenticated,
        privacyAccepted: !!session.privacyAccepted,
      }, nonce, session, isNew);
    }

    if (!url.pathname.startsWith("/api/")) {
      const headers = secureHeaders(nonce, session, isNew);
      headers.set("Content-Type", "text/plain; charset=utf-8");
      return new Response("Not found.", { status: 404, headers });
    }

    if (request.method !== "POST") {
      const headers = secureHeaders(nonce, session, isNew);
      headers.set("Content-Type", "text/plain; charset=utf-8");
      return new Response("Method not allowed.", { status: 405, headers });
    }

    if (!csrfValid(request, session)) {
      return genericError("Your security check expired. Refresh this page and try again.", nonce, session, isNew, 403);
    }

    const body = await requestBody(request);
    if (!body) return genericError("We could not read that request. Please try again.", nonce, session, isNew);

    if (url.pathname === "/api/recovery") {
      if (!validIdentifier(body.identifier)) {
        return genericError("Please enter a valid account email or account ID.", nonce, session, isNew);
      }

      // A new recovery attempt always removes old authenticated and accepted-privacy authority.
      clearAccountAuthority(session);
      session.recoveryRequested = false;
      session.recoveryAccountKey = undefined;
      session.recoveryTokenHash = undefined;
      session.recoveryVerified = false;
      session.demoDeliveryCode = undefined;

      const accountKey = approvedAccountFor(body.identifier) || `unapproved:${sha256(normalizedIdentifier(body.identifier))}`;
      const limit = actionAllowed(request, session, "recovery", accountKey, 5);
      if (!limit.allowed) {
        return genericError(`For safety, please wait about ${limit.retry} seconds before another request. Your progress is safe.`, nonce, session, isNew, 429);
      }

      const approvedAccount = approvedAccountFor(body.identifier);
      // Requirements 3/4: every request receives an opaque random code, but only approved demo code is valid.
      const token = randomToken(32);
      session.recoveryRequested = true;
      session.demoDeliveryCode = token;

      if (approvedAccount) {
        const tokenHash = sha256(token);
        resets.set(tokenHash, {
          tokenHash,
          accountKey: approvedAccount,
          expiresAt: Date.now() + RESET_LIFETIME,
          used: false,
        });
        session.recoveryAccountKey = approvedAccount;
      }

      // Requirements 1/4: approved and unapproved valid recovery requests have identical status, message, and shape.
      return json({
        ok: true,
        message: "If this account can receive recovery messages, a secure recovery code has been sent.",
        recoveryRequested: true,
      }, nonce, session, isNew);
    }

    // Requirements 4: controlled synthetic-delivery mechanism. It returns an indistinguishable opaque code
    // for every recovery session, so it does not reveal whether the submitted account was approved.
    if (url.pathname === "/api/demo/recovery-code") {
      if (!session.recoveryRequested || !session.demoDeliveryCode) {
        return genericError("Please start a recovery request before opening the simulated delivery.", nonce, session, isNew, 403);
      }
      return json({
        ok: true,
        message: "Simulated recovery delivery is ready.",
        mockRecoveryCode: session.demoDeliveryCode,
        recoveryLink: `/recovery-link?token=${encodeURIComponent(session.demoDeliveryCode)}`,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/verify") {
      const accountKey = session.recoveryAccountKey || "no-recovery-account";
      const limit = actionAllowed(request, session, "verify", accountKey, 8);
      if (!limit.allowed) return genericError(`For safety, please wait about ${limit.retry} seconds before trying another code.`, nonce, session, isNew, 429);
      if (!session.recoveryRequested || !session.recoveryAccountKey || !validToken(body.token)) {
        return genericError("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      }

      const tokenHash = sha256(body.token);
      const reset = resets.get(tokenHash);
      if (!reset || reset.accountKey !== session.recoveryAccountKey) return genericError("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      if (reset.used) return genericError("That recovery code has already been used. Request a new one when ready.", nonce, session, isNew);
      if (Date.now() > reset.expiresAt) return genericError("That recovery code has expired. Request a new one when ready.", nonce, session, isNew);

      session.recoveryTokenHash = tokenHash;
      session.recoveryVerified = true;
      return json({ ok: true, message: "Recovery code confirmed. You can now create a new password." }, nonce, session, isNew);
    }

    if (url.pathname === "/api/password") {
      const accountKey = session.recoveryAccountKey || "no-recovery-account";
      const limit = actionAllowed(request, session, "password", accountKey, 5);
      if (!limit.allowed) return genericError(`For safety, please wait about ${limit.retry} seconds before another password attempt.`, nonce, session, isNew, 429);
      if (!session.recoveryVerified || !session.recoveryTokenHash || !session.recoveryAccountKey) {
        return genericError("Please verify a recovery code before creating a password.", nonce, session, isNew, 403);
      }

      const policyFailure = passwordPolicy(body.password);
      if (policyFailure) return genericError(policyFailure, nonce, session, isNew);
      if (body.password !== body.confirm) return genericError("The two passwords do not match. Please try again.", nonce, session, isNew);

      const reset = resets.get(session.recoveryTokenHash);
      if (!reset || reset.used || reset.accountKey !== session.recoveryAccountKey || Date.now() > reset.expiresAt) {
        session.recoveryVerified = false;
        return genericError("Your recovery code is no longer available. Please request a new code.", nonce, session, isNew, 403);
      }

      // Requirements 3/4: reserve the valid token synchronously before awaiting bcrypt hashing.
      reset.used = true;
      try {
        accountPasswordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 10 });
      } catch {
        return genericError("We could not save that password. Please request a new recovery code.", nonce, session, isNew, 503);
      }

      session.recoveryVerified = false;
      session.recoveryRequested = false;
      session.recoveryTokenHash = undefined;
      session.demoDeliveryCode = undefined;

      // Requirements 4: password update cannot retain prior authority; only a successful MFA can authenticate.
      clearAccountAuthority(session);
      session.pendingMfa = true;
      session.mfaAccountKey = reset.accountKey;

      return json({
        ok: true,
        message: "Your new password was saved securely. Confirm the security code to continue.",
        mockMfaCode: MFA_CODE,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/login") {
      const accountKey = approvedAccountFor(body.identifier) || `unapproved:${sha256(validIdentifier(body.identifier) ? normalizedIdentifier(body.identifier) : "invalid")}`;
      const limit = actionAllowed(request, session, "login", accountKey, 5);
      if (!limit.allowed) return genericError(`For safety, please wait about ${limit.retry} seconds before another sign-in attempt.`, nonce, session, isNew, 429);

      const approvedAccount = approvedAccountFor(body.identifier);
      if (!approvedAccount || typeof body.password !== "string" || body.password.length > 128) {
        return genericError("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);
      }

      const matched = await Bun.password.verify(body.password, accountPasswordHash);
      if (!matched) return genericError("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);

      // Requirements 4: a password match is not an authenticated state; MFA is required.
      clearAccountAuthority(session);
      session.pendingMfa = true;
      session.mfaAccountKey = approvedAccount;
      return json({
        ok: true,
        message: "Password checked. Please confirm your security code.",
        mockMfaCode: MFA_CODE,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/mfa") {
      const limit = actionAllowed(request, session, "mfa", session.mfaAccountKey || "no-mfa-account", 6);
      if (!limit.allowed) return genericError(`For safety, please wait about ${limit.retry} seconds before another code attempt.`, nonce, session, isNew, 429);
      if (!session.pendingMfa || !session.mfaAccountKey) {
        return genericError("Please sign in or reset your password before confirming a security code.", nonce, session, isNew, 403);
      }
      if (typeof body.code !== "string" || body.code !== MFA_CODE) {
        return genericError("That security code is not correct. Please check the secure message and try again.", nonce, session, isNew, 401);
      }

      // Requirements 4: this is the sole path that establishes an authenticated state.
      session.pendingMfa = false;
      session.authenticated = true;
      session.privacyAccepted = false;
      return json({ ok: true, message: "Security code confirmed. You are signed in." }, nonce, session, isNew);
    }

    if (url.pathname === "/api/privacy/accept") {
      const limit = actionAllowed(request, session, "privacy", session.mfaAccountKey || "no-authenticated-account", 8);
      if (!limit.allowed) return genericError(`For safety, please wait about ${limit.retry} seconds before another request.`, nonce, session, isNew, 429);
      if (!session.authenticated) {
        return genericError("Please sign in securely before accepting privacy conditions.", nonce, session, isNew, 403);
      }
      session.privacyAccepted = true;
      return json({
        ok: true,
        message: "Privacy conditions accepted. The simulated appointment-booking handoff is ready.",
      }, nonce, session, isNew);
    }

    return genericError("This secure action is not available.", nonce, session, isNew, 404);
  },
  error() {
    // Requirements 3: production-safe error has the same security-header baseline.
    const headers = secureHeaders(randomToken(18));
    headers.set("Content-Type", "text/plain; charset=utf-8");
    return new Response("Secure service unavailable.", { status: 503, headers });
  },
});

console.log(`Hospital recovery server running securely at https://localhost:${server.port}`);
