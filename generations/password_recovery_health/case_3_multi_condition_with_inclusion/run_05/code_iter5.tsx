
import { createHash, randomBytes } from "crypto";

// Requirements 3: TLS-only Bun server using supplied local development certificates.
const PORT = Number(process.env.PORT || 3000);
const CERT_FILE = Bun.file("certs/cert.pem");
const KEY_FILE = Bun.file("certs/key.pem");

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryRequested?: boolean;
  recoveryAccountKey?: string;
  recoveryVerified?: boolean;
  resetGrantHash?: string;
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

type ResetGrant = {
  grantHash: string;
  sessionId: string;
  accountKey: string;
  expiresAt: number;
  used: boolean;
};

const sessions = new Map<string, Session>();
const resets = new Map<string, ResetRecord>();
const resetGrants = new Map<string, ResetGrant>();
const rateWindows = new Map<string, number[]>();

// Requirements 4: synthetic approved demo identifier only; patient identifiers are never exposed.
const DEMO_APPROVED_IDENTIFIER = "helena.demo@hospital.test";
const DEMO_ACCOUNT_KEY = "approved-mock-account";
const MFA_CODE = "246810";
const SESSION_MAX_AGE = 60 * 60 * 8;
const RESET_LIFETIME = 15 * 60 * 1000;
const GRANT_LIFETIME = 10 * 60 * 1000;

let accountPasswordHash =
  process.env.MOCK_ACCOUNT_PASSWORD_HASH ||
  "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

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
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const at = item.indexOf("=");
    if (at > 0) result[item.slice(0, at).trim()] = decodeURIComponent(item.slice(at + 1).trim());
  }
  return result;
}

// Requirements 1/3: sessions are server-side, HttpOnly, Secure, SameSite, and expire safely.
function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const sid = parseCookies(request).hospital_session;
  if (sid) {
    const current = sessions.get(sid);
    if (current && Date.now() - current.createdAt < SESSION_MAX_AGE * 1000) {
      return { session: current, isNew: false };
    }
    sessions.delete(sid);
  }
  const session: Session = { id: randomToken(), csrf: randomToken(), createdAt: Date.now() };
  sessions.set(session.id, session);
  return { session, isNew: true };
}

// Requirements 3: CSP, HSTS, clickjacking, MIME, referrer, and permissions protections.
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

function json(value: Record<string, unknown>, nonce: string, session?: Session, isNew = false, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: secureHeaders(nonce, session, isNew) });
}

function fail(message: string, nonce: string, session: Session, isNew: boolean, status = 400): Response {
  return json({ ok: false, message }, nonce, session, isNew, status);
}

// Requirements 4: per-session and source/account throttling blocks automated guessing.
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

function stableSource(request: Request): string {
  try {
    return server.requestIP(request)?.address || "unavailable-source";
  } catch {
    return "unavailable-source";
  }
}

function actionAllowed(request: Request, session: Session, action: string, account: string, maximum: number) {
  const period = 15 * 60 * 1000;
  const source = sha256(stableSource(request));
  const perSession = rateAllowed(`${action}:session:${session.id}`, maximum, period);
  const perSource = rateAllowed(`${action}:source:${source}:account:${account}`, maximum, period);
  return !perSession.allowed ? perSession : perSource;
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.trim().length >= 3 && value.trim().length <= 120 &&
    /^[A-Za-z0-9@._+\- ]+$/.test(value.trim());
}

function normalizedIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

function approvedAccountFor(value: unknown): string | null {
  return validIdentifier(value) && approvedIdentifierHashes.has(sha256(normalizedIdentifier(value)))
    ? DEMO_ACCOUNT_KEY
    : null;
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{20,120}$/.test(value);
}

function passwordPolicy(value: unknown): string | null {
  if (typeof value !== "string") return "Please enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Please use 128 characters or fewer.";
  if (/\s/.test(value)) return "Please do not use spaces in this password.";
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/\d/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return "Include an uppercase letter, lowercase letter, number, and symbol.";
  }
  return null;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// Requirements 1: every sensitive POST, including grant replacement, validates this per-session CSRF token.
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length > 0 && supplied === session.csrf;
}

function clearAccountAuthority(session: Session): void {
  session.authenticated = false;
  session.privacyAccepted = false;
  session.pendingMfa = false;
  session.mfaAccountKey = undefined;
}

// Requirements 3/4: invalidate a grant without erasing a valid completed recovery-code step.
function invalidateResetGrant(session: Session): void {
  if (session.resetGrantHash) {
    const grant = resetGrants.get(session.resetGrantHash);
    if (grant) grant.used = true;
  }
  session.resetGrantHash = undefined;
}

function clearRecoveryGrant(session: Session): void {
  invalidateResetGrant(session);
  session.recoveryVerified = false;
}

// Requirements 3: grants are random, single-use, short-lived, session/account-bound server records.
function issueReplacementGrant(session: Session): string | null {
  if (!session.recoveryVerified || !session.recoveryAccountKey) return null;
  invalidateResetGrant(session);
  const value = randomToken(32);
  const grantHash = sha256(value);
  resetGrants.set(grantHash, {
    grantHash,
    sessionId: session.id,
    accountKey: session.recoveryAccountKey,
    expiresAt: Date.now() + GRANT_LIFETIME,
    used: false,
  });
  session.resetGrantHash = grantHash;
  return value;
}

function currentRecoveryStep(session: Session): string {
  if (session.authenticated && session.privacyAccepted) return "confirmation";
  if (session.authenticated) return "privacy";
  if (session.pendingMfa) return "mfa";

  if (session.resetGrantHash) {
    const grant = resetGrants.get(session.resetGrantHash);
    if (!grant || grant.used || grant.sessionId !== session.id || grant.expiresAt <= Date.now()) {
      // A grant can expire, but the server-confirmed recovery-code step is retained for replacement.
      session.resetGrantHash = undefined;
    }
  }
  if (session.recoveryVerified && session.recoveryAccountKey) return "password";
  if (session.recoveryRequested) return "verify";
  return "start";
}

function appHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{--navy:#12324a;--blue:#176b9d;--pale:#edf6fa;--line:#c8d8e1;--ink:#17232b;--good:#126943;--warn:#8a4a00;--bad:#a22525}*{box-sizing:border-box}body{margin:0;background:#f6f9fa;color:var(--ink);font:18px/1.5 Arial,sans-serif}header{background:var(--navy);color:#fff;padding:1rem 1.4rem}.brand{font-weight:700;font-size:1.25rem}header p{font-size:.92rem;margin:.15rem 0}main{max-width:1040px;margin:auto;padding:1.4rem;display:grid;grid-template-columns:245px minmax(0,1fr);gap:1.4rem}aside,section,.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.15rem;box-shadow:0 1px 2px #12253512}h1{font-size:1.7rem;line-height:1.2;margin:0 0 .6rem}h2{font-size:1.2rem;margin:.2rem 0 .65rem}p{margin:.45rem 0 1rem}.steps{list-style:none;padding:0;margin:.5rem 0}.steps li{padding:.5rem;border-left:5px solid #cedae0;margin:.3rem 0;color:#52636c}.steps .active{border-color:var(--blue);background:var(--pale);color:var(--ink);font-weight:bold}.steps .done{border-color:var(--good);color:var(--good)}label{display:block;font-weight:bold;margin-top:.85rem}input{display:block;width:100%;max-width:520px;margin-top:.25rem;padding:.7rem;border:2px solid #8097a3;border-radius:6px;font-size:1rem}input:focus,button:focus{outline:3px solid #f1b43b;outline-offset:2px}button{display:inline-block;margin:.9rem .55rem 0 0;background:var(--blue);color:white;border:0;border-radius:6px;padding:.7rem 1rem;font-size:1rem;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:var(--navy);border:2px solid var(--blue)}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .85rem;margin:.8rem 0}.success{border-color:var(--good);background:#ecf8f1}.warning{border-color:var(--warn);background:#fff6e8}.error{border-color:var(--bad);background:#fff0f0}.small{font-size:.92rem}.muted{color:#52636c}.help{margin-top:1rem;background:#fff9e9}.logs{margin-top:1rem;background:#10232e;color:#e3f7ff;border-radius:7px;padding:.65rem;max-height:175px;overflow:auto;font:13px/1.4 monospace;white-space:pre-wrap}.policy{padding-left:1.2rem}.policy li{margin:.25rem 0}code{background:#e8f0f4;padding:.1rem .3rem;border-radius:3px;overflow-wrap:anywhere}@media(max-width:760px){main{display:block;padding:1rem}aside{margin-bottom:1rem}}
</style>
</head>
<body>
<header><div class="brand">Hospital secure account portal</div><p>Check that the address begins with <strong>https://localhost</strong>. We never ask for a password or code by email or phone.</p></header>
<main>
<aside aria-label="Recovery progress">
<h2>Your progress</h2><ol id="steps" class="steps"></ol>
<button id="pauseButton" class="secondary" type="button">Pause and return later</button>
<button id="resumeButton" class="secondary" type="button" hidden>Resume recovery</button>
<p class="small muted">There is no action countdown. The server keeps your confirmed step while its security session remains valid.</p>
</aside>
<section aria-live="polite">
<div id="content"></div>
<div class="card help"><h2>Help and safe sign-in</h2><p>If anything feels unclear, pause here. You can use Resume recovery when you are ready in this browser.</p><p class="small">Only enter passwords and one-time codes on this HTTPS hospital page. Hospital staff will never ask you to read them aloud.</p><button id="helpButton" class="secondary" type="button">Show a short reminder</button><div id="helpMessage" class="notice" hidden></div></div>
<h2 class="small">Activity logs for this demonstration</h2><div id="logs" class="logs">Ready. Security events will appear here.</div>
</section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
// Requirements 2: all displayed values use textContent and DOM nodes, never untrusted HTML.
const content=document.getElementById("content"),stepsNode=document.getElementById("steps"),logs=document.getElementById("logs"),pauseButton=document.getElementById("pauseButton"),resumeButton=document.getElementById("resumeButton"),helpMessage=document.getElementById("helpMessage");
const demoIdentifier="helena.demo@hospital.test";
const steps=[["start","1. Start"],["verify","2. Check recovery code"],["password","3. Create password"],["mfa","4. Confirm security code"],["privacy","5. Accept privacy conditions"],["confirmation","6. Finished"]];
let csrf="",screen="start",resetGrant="",rememberedLinkToken=new URLSearchParams(location.search).get("token")||"";
function log(s){console.log(s);logs.textContent+="\\n"+s;logs.scrollTop=logs.scrollHeight}
function el(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n}
function btn(text,cls){const n=el("button",text);n.type="button";if(cls)n.className=cls;return n}
function note(text,kind){const n=el("div",text);n.className="notice "+(kind||"");return n}
function field(form,labelText,type,name,auto){const l=el("label",labelText),i=document.createElement("input");i.type=type;i.name=name;i.id=name;i.required=true;i.autocomplete=auto||"off";l.htmlFor=name;form.append(l,i);return i}
function message(text,kind){const old=content.querySelector(".response-message");if(old)old.remove();const n=note(text,kind);n.classList.add("response-message");content.append(n)}
function setSteps(){stepsNode.replaceChildren();let active=Math.max(0,steps.findIndex(x=>x[0]===screen));steps.forEach((x,i)=>{const n=el("li",x[1]);if(i===active)n.className="active";else if(i<active)n.className="done";stepsNode.append(n)})}
async function api(path,body){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});const d=await r.json();if(!r.ok&&!d.message)d.message="We could not complete that step. Please try again.";return d}catch{return{ok:false,message:"Connection unavailable. Your progress is still saved; please try again."}}}
async function status(){const r=await fetch("/api/status",{credentials:"same-origin"});const d=await r.json();csrf=d.csrf||csrf;return d}
function render(){content.replaceChildren();setSteps();if(screen==="start")start();else if(screen==="verify")verify();else if(screen==="password")password();else if(screen==="mfa")mfa();else if(screen==="privacy")privacy();else confirmation()}
// Requirements ADHD/inclusivity: pause is explicit, progress is visible, and no browser secret is retained.
pauseButton.addEventListener("click",()=>{localStorage.setItem("hospital-recovery-paused","yes");resumeButton.hidden=false;log("Recovery paused locally. No password, recovery code, or reset grant was saved in the browser.");message("Paused. The server-confirmed step is preserved while your secure session is valid. Recovery codes and replacement reset grants still expire for security.","warning")});
resumeButton.addEventListener("click",async()=>{const d=await status();screen=d.recoveryStep||"start";localStorage.removeItem("hospital-recovery-paused");resumeButton.hidden=true;if(screen==="password"){await preparePassword();return}resetGrant="";log("Recovery resumed at the current server-confirmed step.");render();message("You are back at your saved secure step. Recovery codes and reset grants remain subject to their security expiration rules.","success")});
document.getElementById("helpButton").addEventListener("click",()=>{helpMessage.hidden=!helpMessage.hidden;helpMessage.textContent="Short reminder: do one step at a time. Use only this HTTPS hospital page, and never share passwords or one-time codes."});
function title(a,b){content.append(el("h1",a),el("p",b))}
// Requirements 3: request a fresh session-bound replacement grant before showing password entry after resume/reload.
async function preparePassword(){resetGrant="";const r=await api("/api/recovery/replacement-grant",{});if(!r.ok){screen="verify";render();message(r.message,"error");return}resetGrant=r.resetGrant||"";screen="password";render();message("Recovery code step is confirmed. A fresh short-lived password-reset approval is ready for this browser session.","success")}
function start(){title("Reset your password","Step 1 of 6. Enter the account email or account ID you use with the hospital.");content.append(note("For privacy, we give the same response whether or not an account can receive a recovery message."));const d=note("","success"),c=el("code",demoIdentifier);d.append("Approved synthetic demonstration identifier: ",c,". This is test data only, not a patient email or account.");content.append(d);const f=document.createElement("form"),id=field(f,"Account email or ID","text","identifier","username");id.maxLength=120;const s=el("button","Send recovery code");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const r=await api("/api/recovery",{identifier:id.value});s.disabled=false;if(!r.ok)return message(r.message,"error");localStorage.removeItem("hospital-recovery-paused");resumeButton.hidden=true;screen="verify";render();message(r.message,"success")});content.append(f,el("p","Next: open the simulated delivery message or enter a recovery code manually.","small"));const login=btn("I know my password — sign in","secondary");login.addEventListener("click",loginPage);content.append(login)}
function loginPage(){content.replaceChildren();title("Sign in securely","Use this only on the hospital HTTPS page. After sign-in, you will confirm a security code.");content.append(note("Anti-phishing reminder: never follow a password request from an email. Type the hospital address yourself.","warning"));const f=document.createElement("form"),id=field(f,"Account email or ID","text","identifier","username"),pw=field(f,"Password","password","password","current-password"),s=el("button","Sign in");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const r=await api("/api/login",{identifier:id.value,password:pw.value});pw.value="";s.disabled=false;if(!r.ok)return message(r.message,"error");log("Mock hospital MFA code: "+r.mockMfaCode+". This demonstration logs the code only in the browser console and activity logs.");screen="mfa";render();message("Password checked. Next, enter the security code.","success")});const reset=btn("I need to reset my password","secondary");reset.addEventListener("click",()=>{screen="start";render()});content.append(f,reset)}
function verify(){title("Check your recovery code","Step 2 of 6. Paste or type the code from the secure hospital recovery message.");content.append(note("You may use either the simulated recovery link or this manual code box. Nothing happens until you choose Verify code."));const delivery=btn("Open simulated recovery delivery","secondary");delivery.addEventListener("click",async()=>{delivery.disabled=true;const r=await api("/api/demo/recovery-code",{});delivery.disabled=false;if(!r.ok)return message(r.message,"error");rememberedLinkToken=r.mockRecoveryCode||"";log("Mock hospital delivery: recovery code "+rememberedLinkToken+". This demonstration logs the code only in the browser console and activity logs.");message("Simulated delivery opened. The code is ready in the box below.","success");const link=btn("Open simulated recovery link","secondary");link.addEventListener("click",()=>location.href=r.recoveryLink);content.append(link)});content.append(delivery);const f=document.createElement("form"),token=field(f,"Recovery code","text","token","one-time-code");token.maxLength=120;if(rememberedLinkToken){token.value=rememberedLinkToken;content.append(note("A recovery link opened this page. The code was placed here for you, but it has not been checked yet.","success"))}const s=el("button","Verify code");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const r=await api("/api/verify",{token:token.value});s.disabled=false;if(!r.ok)return message(r.message,"error");rememberedLinkToken="";history.replaceState({},"","/");await preparePassword()});const back=btn("Back to recovery request","secondary");back.addEventListener("click",()=>{screen="start";render()});content.append(f,back,el("p","Recovery codes expire after 15 minutes and can only be used once.","small muted"))}
function password(){title("Create a strong password","Step 3 of 6. Choose a new password. We will not show or log it.");const list=el("ul");list.className="policy";["At least 12 characters","An uppercase letter and lowercase letter","A number and a symbol","No spaces"].forEach(x=>list.append(el("li",x)));content.append(el("h2","Password checklist"),list);const f=document.createElement("form"),pw=field(f,"New password","password","password","new-password"),cf=field(f,"Confirm new password","password","confirm","new-password"),s=el("button","Save new password");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();if(!resetGrant){await preparePassword();return}s.disabled=true;const r=await api("/api/password",{password:pw.value,confirm:cf.value,grant:resetGrant});pw.value=cf.value="";s.disabled=false;if(!r.ok)return message(r.message,"error");resetGrant="";log("Mock hospital MFA code: "+r.mockMfaCode+". This demonstration logs the code only in the browser console and activity logs.");screen="mfa";render();message("New password saved securely. Next, confirm your security code.","success")});content.append(f,el("p","This replacement approval is short-lived and single-use. Reloading safely requests a new one for this verified session.","small muted"))}
function mfa(){title("Confirm your security code","Step 4 of 6. This extra check protects your account after a password reset or sign-in.");content.append(note("Enter the one-time code from the secure hospital message. Never share this code with anyone.","warning"));const f=document.createElement("form"),code=field(f,"Security code","text","code","one-time-code");code.inputMode="numeric";code.maxLength=12;const s=el("button","Confirm code");s.type="submit";f.append(s);f.addEventListener("submit",async e=>{e.preventDefault();s.disabled=true;const r=await api("/api/mfa",{code:code.value});s.disabled=false;code.value="";if(!r.ok)return message(r.message,"error");screen="privacy";render();message(r.message,"success")});content.append(f)}
function privacy(){title("Review updated privacy conditions","Step 5 of 6. You are signed in. Read this short summary, then choose one clear action.");content.append(note("Your healthcare account information is protected. This page does not display patient identifiers.","success"));const l=el("ul");l.className="policy";["Hospital authorities may use your account confirmation to arrange your requested appointment.","Only authorised hospital staff may access necessary health information.","You can ask the hospital for help with these conditions at any time."].forEach(x=>l.append(el("li",x)));content.append(el("h2","Summary"),l);const a=btn("Accept updated privacy conditions");a.addEventListener("click",async()=>{a.disabled=true;const r=await api("/api/privacy/accept",{});a.disabled=false;if(!r.ok)return message(r.message,"error");screen="confirmation";render()});content.append(a)}
function confirmation(){title("You are all set","Step 6 of 6. The updated privacy conditions have been recorded.");content.append(note("Simulated appointment-booking handoff completed. Hospital staff can now continue with the medication review appointment request.","success"),el("p","You may safely close this page. No patient details are shown here."));const r=btn("Return to secure start","secondary");r.addEventListener("click",()=>{screen="start";render()});content.append(r)}
async function bootstrap(){try{const d=await status();screen=rememberedLinkToken?"verify":(d.recoveryStep||"start");if(localStorage.getItem("hospital-recovery-paused")==="yes"){resumeButton.hidden=false;log("A paused recovery reminder was found. Select Resume recovery whenever you feel ready.")}if(screen==="password"){await preparePassword();return}render()}catch{content.textContent="Secure connection could not be established. Please refresh this hospital page."}}
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
      const step = currentRecoveryStep(session);
      return json({
        ok: true,
        csrf: session.csrf,
        recoveryRequested: !!session.recoveryRequested,
        recoveryVerified: step === "password",
        pendingMfa: !!session.pendingMfa,
        authenticated: !!session.authenticated,
        privacyAccepted: !!session.privacyAccepted,
        recoveryStep: step,
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
      return fail("Your security check expired. Refresh this page and try again.", nonce, session, isNew, 403);
    }

    const body = await requestBody(request);
    if (!body) return fail("We could not read that request. Please try again.", nonce, session, isNew);

    // Requirements 1/3: only this session at the verified password step can replace its prior grant.
    if (url.pathname === "/api/recovery/replacement-grant") {
      if (currentRecoveryStep(session) !== "password" || !session.recoveryVerified || !session.recoveryAccountKey) {
        return fail("Please verify a recovery code before preparing a new password.", nonce, session, isNew, 403);
      }
      const limit = actionAllowed(request, session, "replacement-grant", session.recoveryAccountKey, 8);
      if (!limit.allowed) {
        return fail(`For safety, please wait about ${limit.retry} seconds before refreshing the password approval.`, nonce, session, isNew, 429);
      }
      const resetGrant = issueReplacementGrant(session);
      if (!resetGrant) return fail("Your secure password-reset step is no longer available. Please request a new recovery code.", nonce, session, isNew, 403);
      return json({
        ok: true,
        message: "A fresh password-reset approval has been prepared for this secure session.",
        resetGrant,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/recovery") {
      if (!validIdentifier(body.identifier)) {
        return fail("Please enter a valid account email or account ID.", nonce, session, isNew);
      }

      clearAccountAuthority(session);
      clearRecoveryGrant(session);
      session.recoveryRequested = false;
      session.recoveryAccountKey = undefined;
      session.demoDeliveryCode = undefined;

      const accountKey = approvedAccountFor(body.identifier) || `unapproved:${sha256(normalizedIdentifier(body.identifier))}`;
      const limit = actionAllowed(request, session, "recovery", accountKey, 5);
      if (!limit.allowed) {
        return fail(`For safety, please wait about ${limit.retry} seconds before another request. Your progress is safe.`, nonce, session, isNew, 429);
      }

      const approvedAccount = approvedAccountFor(body.identifier);
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

      return json({
        ok: true,
        message: "If this account can receive recovery messages, a secure recovery code has been sent.",
        recoveryRequested: true,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/demo/recovery-code") {
      if (!session.recoveryRequested || !session.demoDeliveryCode) {
        return fail("Please start a recovery request before opening the simulated delivery.", nonce, session, isNew, 403);
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
      if (!limit.allowed) return fail(`For safety, please wait about ${limit.retry} seconds before trying another code.`, nonce, session, isNew, 429);
      if (!session.recoveryRequested || !session.recoveryAccountKey || !validToken(body.token)) {
        return fail("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      }

      const tokenHash = sha256(body.token);
      const reset = resets.get(tokenHash);
      if (!reset || reset.accountKey !== session.recoveryAccountKey) {
        return fail("That recovery code is invalid. Check it and try again.", nonce, session, isNew);
      }
      if (reset.used) return fail("That recovery code has already been used. Request a new one when ready.", nonce, session, isNew);
      if (Date.now() > reset.expiresAt) return fail("That recovery code has expired. Request a new one when ready.", nonce, session, isNew);

      // Requirements 3/4: consume recovery code immediately; it cannot be replayed.
      reset.used = true;
      clearRecoveryGrant(session);
      session.recoveryVerified = true;

      return json({
        ok: true,
        message: "Recovery code confirmed. Preparing your secure password step.",
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/password") {
      const accountKey = session.recoveryAccountKey || "no-recovery-account";
      const limit = actionAllowed(request, session, "password", accountKey, 5);
      if (!limit.allowed) return fail(`For safety, please wait about ${limit.retry} seconds before another password attempt.`, nonce, session, isNew, 429);

      if (!session.recoveryVerified || !session.resetGrantHash || !session.recoveryAccountKey || !validToken(body.grant)) {
        return fail("Please refresh the password step to prepare a secure approval.", nonce, session, isNew, 403);
      }

      const suppliedGrantHash = sha256(body.grant);
      const grant = resetGrants.get(suppliedGrantHash);
      if (
        !grant ||
        grant.used ||
        grant.expiresAt <= Date.now() ||
        grant.sessionId !== session.id ||
        grant.accountKey !== session.recoveryAccountKey ||
        suppliedGrantHash !== session.resetGrantHash
      ) {
        invalidateResetGrant(session);
        return fail("This password-reset approval has expired or was already used. Refresh this password step for a replacement approval.", nonce, session, isNew, 403);
      }

      const policyFailure = passwordPolicy(body.password);
      if (policyFailure) return fail(policyFailure, nonce, session, isNew);
      if (body.password !== body.confirm) return fail("The two passwords do not match. Please try again.", nonce, session, isNew);

      // Requirements 3/4: reserve the single-use grant before bcrypt hashing prevents concurrent replay.
      grant.used = true;
      try {
        accountPasswordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 10 });
      } catch {
        clearRecoveryGrant(session);
        return fail("We could not save that password. Please request a new recovery code.", nonce, session, isNew, 503);
      }

      session.resetGrantHash = undefined;
      session.recoveryVerified = false;
      session.recoveryRequested = false;
      session.demoDeliveryCode = undefined;

      // Requirements 4: MFA is mandatory after password reset.
      clearAccountAuthority(session);
      session.pendingMfa = true;
      session.mfaAccountKey = grant.accountKey;

      return json({
        ok: true,
        message: "Your new password was saved securely. Confirm the security code to continue.",
        mockMfaCode: MFA_CODE,
      }, nonce, session, isNew);
    }

    if (url.pathname === "/api/login") {
      const accountKey = approvedAccountFor(body.identifier) ||
        `unapproved:${sha256(validIdentifier(body.identifier) ? normalizedIdentifier(body.identifier) : "invalid")}`;
      const limit = actionAllowed(request, session, "login", accountKey, 5);
      if (!limit.allowed) return fail(`For safety, please wait about ${limit.retry} seconds before another sign-in attempt.`, nonce, session, isNew, 429);

      const approvedAccount = approvedAccountFor(body.identifier);
      if (!approvedAccount || typeof body.password !== "string" || body.password.length > 128) {
        return fail("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);
      }

      const matched = await Bun.password.verify(body.password, accountPasswordHash);
      if (!matched) return fail("We could not sign you in. Check your details and try again.", nonce, session, isNew, 401);

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
      if (!limit.allowed) return fail(`For safety, please wait about ${limit.retry} seconds before another code attempt.`, nonce, session, isNew, 429);
      if (!session.pendingMfa || !session.mfaAccountKey) {
        return fail("Please sign in or reset your password before confirming a security code.", nonce, session, isNew, 403);
      }
      if (typeof body.code !== "string" || body.code !== MFA_CODE) {
        return fail("That security code is not correct. Please check the secure message and try again.", nonce, session, isNew, 401);
      }

      session.pendingMfa = false;
      session.authenticated = true;
      session.privacyAccepted = false;
      return json({ ok: true, message: "Security code confirmed. You are signed in." }, nonce, session, isNew);
    }

    if (url.pathname === "/api/privacy/accept") {
      const limit = actionAllowed(request, session, "privacy", session.mfaAccountKey || "no-authenticated-account", 8);
      if (!limit.allowed) return fail(`For safety, please wait about ${limit.retry} seconds before another request.`, nonce, session, isNew, 429);
      if (!session.authenticated) {
        return fail("Please sign in securely before accepting privacy conditions.", nonce, session, isNew, 403);
      }
      session.privacyAccepted = true;
      return json({
        ok: true,
        message: "Privacy conditions accepted. The simulated appointment-booking handoff is ready.",
      }, nonce, session, isNew);
    }

    return fail("This secure action is not available.", nonce, session, isNew, 404);
  },
  error() {
    const headers = secureHeaders(randomToken(18));
    headers.set("Content-Type", "text/plain; charset=utf-8");
    return new Response("Secure service unavailable.", { status: 503, headers });
  },
});

console.log(`Hospital recovery server running securely at https://localhost:${server.port}`);
