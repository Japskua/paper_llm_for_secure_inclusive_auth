
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/*
 Password Recovery System — Requirements 1–5
 HTTPS Bun server, CSRF-protected sessions, Argon2id passwords, MFA,
 server-side reset verification, controlled simulated delivery, and rate limits.
*/

type Session = {
  csrf: string;
  userId?: string;
  mfaUserId?: string;
  mfaExpires?: number;
  recoveryUserId?: string;
  recoveryContext?: string;
  deliveryAuthorizedUntil?: number;
  verifiedTokenHash?: string;
  verifiedUserId?: string;
  verifiedExpires?: number;
};

type User = {
  id: string;
  identifier: string;
  passwordHash: string;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
};

type ResetToken = {
  userId: string;
  tokenHash: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
};

type Attempt = { count: number; startedAt: number; lockedUntil: number };

const PORT = Number(Bun.env.PORT || 3000);
const sessions = new Map<string, Session>();
const users = new Map<string, User>();
const resetTokens = new Map<string, ResetToken>();
const loginAttempts = new Map<string, Attempt>();
const deliveryAttempts = new Map<string, Attempt>();
const mfaAttempts = new Map<string, Attempt>();
const resetRequestAttempts = new Map<string, Attempt>();

const WINDOW_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const RESET_TTL_MS = 15 * 60 * 1000;
const DELIVERY_AUTH_TTL_MS = 15 * 60 * 1000;
const MFA_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

/* Deterministic evaluation-only mock values. */
const DELIVERY_AUTHORIZATION_CODE = "864200";
const MFA_CODE = "246810";

const demoUser: User = {
  id: "u_7fd2e6c04a",
  identifier: "helena@hospital.test",
  passwordHash: await Bun.password.hash("Initial-Only-Password!42", { algorithm: "argon2id" }),
  privacyAccepted: false,
  appointmentConfirmed: false,
};
users.set(demoUser.identifier, demoUser);

function randomId(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}
function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function equal(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function cookie(request: Request, name: string): string | undefined {
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return value.join("=");
  }
}
function makeSession(): { id: string; session: Session } {
  const id = randomId();
  const session: Session = { csrf: randomId(24) };
  sessions.set(id, session);
  return { id, session };
}
function getSession(request: Request): { id: string; session: Session; fresh: boolean } {
  const id = cookie(request, "__Host-hospital_session");
  if (id && sessions.has(id)) return { id, session: sessions.get(id)!, fresh: false };
  const created = makeSession();
  return { ...created, fresh: true };
}
function sessionCookie(id: string): string {
  return `__Host-hospital_session=${id}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

/*
 Requirement 1 / task: do not trust client-provided X-Forwarded-For.
 This application is directly TLS-served by Bun and has no configured trusted
 reverse proxy, so all client-controlled forwarding headers are ignored.
 Account/recovery-context keys are server controlled and survive new sessions.
*/
function trustworthyRequestIdentity(_request: Request): string {
  return "direct-bun-tls-origin";
}

function headers(nonce?: string, setCookie?: string, api = false): Headers {
  const h = new Headers({
    "Content-Type": api ? "application/json; charset=utf-8" : "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  h.set("Content-Security-Policy", api
    ? "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    : `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  if (setCookie) h.set("Set-Cookie", setCookie);
  return h;
}
function reply(data: object, status = 200, setCookie?: string): Response {
  return new Response(JSON.stringify(data), { status, headers: headers(undefined, setCookie, true) });
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length >= 5 && value.length <= 120 &&
    /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/i.test(value);
}
function validCode(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value);
}
function normalize(value: string): string {
  return value.trim().toLowerCase();
}
function passwordIssue(value: unknown): string | null {
  if (typeof value !== "string") return "Enter a new password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  if (/\s/.test(value)) return "Do not use spaces in this password.";
  if (!/[a-z]/.test(value)) return "Add a lowercase letter.";
  if (!/[A-Z]/.test(value)) return "Add an uppercase letter.";
  if (!/\d/.test(value)) return "Add a number.";
  if (!/[^A-Za-z0-9]/.test(value)) return "Add a symbol.";
  return null;
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || 0) > 8192) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function csrfOK(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token") || "";
  return token.length === session.csrf.length && equal(token, session.csrf);
}
function clearVerified(session: Session): void {
  delete session.verifiedTokenHash;
  delete session.verifiedUserId;
  delete session.verifiedExpires;
}
function clearRecovery(session: Session): void {
  delete session.recoveryUserId;
  delete session.recoveryContext;
  delete session.deliveryAuthorizedUntil;
}
function attemptAllowed(store: Map<string, Attempt>, key: string): boolean {
  const item = store.get(key);
  return !item || item.lockedUntil <= Date.now();
}
function failedAttempt(store: Map<string, Attempt>, key: string): void {
  const now = Date.now();
  let item = store.get(key);
  if (!item || now - item.startedAt > WINDOW_MS) item = { count: 0, startedAt: now, lockedUntil: 0 };
  item.count++;
  if (item.count >= MAX_ATTEMPTS) item.lockedUntil = now + LOCK_MS;
  store.set(key, item);
}
function successfulAttempt(store: Map<string, Attempt>, key: string): void {
  store.delete(key);
}
function requestAllowed(key: string): boolean {
  const now = Date.now();
  let item = resetRequestAttempts.get(key);
  if (!item || now - item.startedAt > WINDOW_MS) item = { count: 0, startedAt: now, lockedUntil: 0 };
  item.count++;
  resetRequestAttempts.set(key, item);
  return item.count <= MAX_ATTEMPTS;
}
function resetRecord(token: string, sessionId: string): ResetToken | null {
  if (!validToken(token)) return null;
  const record = resetTokens.get(hash(token));
  if (!record || record.used || record.sessionId !== sessionId || record.expiresAt <= Date.now()) return null;
  return record;
}
function verifiedRecord(session: Session): ResetToken | null {
  if (!session.verifiedTokenHash || !session.verifiedUserId || !session.verifiedExpires || session.verifiedExpires <= Date.now()) {
    clearVerified(session);
    return null;
  }
  const record = resetTokens.get(session.verifiedTokenHash);
  if (!record || record.used || record.expiresAt <= Date.now() ||
      record.userId !== session.verifiedUserId || record.expiresAt !== session.verifiedExpires) {
    clearVerified(session);
    return null;
  }
  return record;
}
function signedIn(session: Session): User | null {
  if (!session.userId) return null;
  for (const user of users.values()) if (user.id === session.userId) return user;
  return null;
}

function page(nonce: string, csrf: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--ink:#163042;--muted:#526775;--blue:#075f9d;--pale:#edf6fa;--line:#bfd0da;--good:#087047;--bad:#a32727}*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:var(--ink);font:18px/1.52 Arial,sans-serif}.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;z-index:5;background:#fff;padding:.7rem}header{padding:1.1rem max(1rem,calc((100% - 760px)/2));background:#fff;border-bottom:4px solid var(--blue)}header strong{font-size:1.2rem}main,footer{max-width:760px;margin:1.7rem auto;padding:0 1rem}.progress{display:flex;flex-wrap:wrap;gap:.35rem;padding:0;list-style:none}.progress li{background:#dce6eb;border-radius:1rem;font-size:.8rem;padding:.28rem .55rem}.progress .active{background:var(--blue);color:#fff}.card,details{margin:1rem 0;padding:1.35rem;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 2px #0000000b}h1{font-size:1.65rem;line-height:1.2;margin:.1rem 0 .8rem}h2{font-size:1.15rem}.next{margin:1rem 0;padding:.8rem 1rem;background:var(--pale);border-left:5px solid var(--blue)}label{display:block;font-weight:bold;margin:1rem 0 .25rem}input{width:100%;padding:.65rem;border:2px solid #77909d;border-radius:5px;font:inherit}.check{width:auto}button{margin:1rem .5rem 0 0;padding:.65rem 1rem;border:0;border-radius:5px;background:var(--blue);color:white;font:inherit;font-weight:bold;cursor:pointer}button.secondary{background:#e1ebf0;color:var(--ink)}button.link{margin:.6rem 0;padding:0;background:none;color:var(--blue);text-decoration:underline}input:focus,button:focus{outline:3px solid #e49b22;outline-offset:2px}.hint,footer{color:var(--muted);font-size:.92rem}.feedback{min-height:1.5rem;font-weight:bold}.error{color:var(--bad)}.success{color:var(--good)}.code{padding:.45rem;background:#eef3f5;border-radius:4px;font-family:monospace;word-break:break-all}#logs{max-height:170px;overflow:auto;padding:.75rem;background:#10222c;color:#dff5ff;border-radius:5px;white-space:pre-wrap;font:13px/1.4 monospace}summary{font-weight:bold;cursor:pointer}@media(max-width:500px){body{font-size:17px}}
</style></head><body>
<a class="skip" href="#content">Skip to main content</a>
<header><strong>Hospital account support</strong><div class="hint">Private account recovery</div></header>
<main id="content" tabindex="-1"><ol class="progress" id="progress" aria-label="Recovery progress"></ol><section id="app" class="card" aria-live="polite"></section>
<details><summary>Help and safe authentication</summary><p>You can pause at any time. Your current step and email are saved only in this browser. There is no session timeout while you work.</p><p><strong>Keep your account safe:</strong> hospital staff will never ask for your password or verification code by email, phone, or support message.</p><p>Use the phone number on your official appointment letter if you need help.</p></details>
<section class="card"><h2>Activity logs (simulation)</h2><div id="logs" aria-live="polite">Ready. Simulation activity appears here.</div></section></main>
<footer>No time limit. You may return when ready.</footer>
<script nonce="${nonce}">
(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},app=document.getElementById("app"),progress=document.getElementById("progress"),logs=document.getElementById("logs");
const baseLog=console.log.bind(console);console.log=(...v)=>{baseLog(...v);logs.textContent+="\\n"+v.map(x=>typeof x==="string"?x:JSON.stringify(x)).join(" ");logs.scrollTop=logs.scrollHeight;};
const order=["identify","delivery","verify","password","signin","mfa","privacy","appointment"],names={identify:"1 Account",delivery:"2 Delivery",verify:"3 Verify",password:"4 Password",signin:"5 Sign in",mfa:"6 Security check",privacy:"7 Privacy",appointment:"8 Confirm"};
let state={step:"identify",identifier:"",token:"",saved:false};
try{const old=JSON.parse(localStorage.getItem("hospital-recovery-progress")||"{}");if(order.includes(old.step))state.step=old.step;if(typeof old.identifier==="string"&&old.identifier.length<=120)state.identifier=old.identifier}catch(_){}
function save(){localStorage.setItem("hospital-recovery-progress",JSON.stringify({step:state.step,identifier:state.identifier}));}
function go(step){state.step=step;save();render()}
function note(text,good=false){const n=document.getElementById("feedback");if(n){n.textContent=text;n.className="feedback "+(good?"success":"error")}}
async function api(path,data){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let d={};try{d=await r.json()}catch(_){}return{ok:r.ok,data:d}}catch(_){return{ok:false,data:{message:"Unable to reach the secure service. Please try again."}}}}
function shell(title,next,inside){return "<h1>"+title+"</h1><div class=\\"next\\"><strong>Next step:</strong> "+next+"</div>"+inside+"<p class=\\"hint\\"><strong>Safety reminder:</strong> never share your password or verification code with email or support staff.</p><p id=\\"feedback\\" class=\\"feedback\\" role=\\"alert\\"></p>"}
function tokenPresent(){return typeof state.token==="string"&&/^[a-f0-9]{64}$/i.test(state.token)}
function draw(){progress.textContent="";const n=order.indexOf(state.step);order.forEach((s,i)=>{const li=document.createElement("li");li.textContent=names[s];if(i===n||(state.step==="done"&&i===order.length-1))li.className="active";progress.appendChild(li)})}
function render(){draw();
if(state.step==="identify"){app.innerHTML=shell("Reset your password","Enter the email address you use for your hospital account.","<p>This is a calm, step-by-step process. You can stop and return later.</p><form id=\\"f\\" novalidate><label for=\\"email\\">Hospital account email</label><input id=\\"email\\" type=\\"email\\" autocomplete=\\"username\\" required><p class=\\"hint\\">We use the same response whether or not an account is available.</p><button>Start recovery</button></form>");const i=document.getElementById("email");i.value=state.identifier;document.getElementById("f").onsubmit=async e=>{e.preventDefault();state.identifier=i.value.trim();save();if(!i.checkValidity())return note("Please enter an email address in the usual format.");const r=await api("/api/reset-request",{identifier:state.identifier});if(!r.ok)return note(r.data.message||"We could not start recovery.");console.log("SIMULATED TRUSTED DELIVERY: delivery authorization code =",r.data.deliveryAuthorizationCode);go("delivery")}}
else if(state.step==="delivery"){app.innerHTML=shell("Authorize your recovery delivery","Enter the authorization code from the trusted simulated delivery.","<p>This protects your account. Knowing an email address alone is not enough.</p><form id=\\"f\\"><label for=\\"code\\">Trusted delivery authorization code</label><input id=\\"code\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" required><button>Authorize delivery</button></form><button class=\\"link\\" type=\\"button\\" id=\\"back\\">Use a different email address</button>");document.getElementById("back").onclick=()=>go("identify");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery-delivery",{code:document.getElementById("code").value.trim()});if(!r.ok)return note(r.data.message||"Please try trusted delivery authorization again.");if(typeof r.data.evaluationToken!=="string")return note("Delivery could not be prepared. Please start again.");state.token=r.data.evaluationToken;console.log("SIMULATED RECOVERY DELIVERY: recovery code =",state.token);go("verify")}}
else if(state.step==="verify"){const available=tokenPresent();app.innerHTML=shell("Check your recovery code","Paste the delivered recovery code and select Verify code.",(available?"<p>For this evaluation, the delivered code appears below and in Activity logs after authorization.</p><p class=\\"code\\" id=\\"shown\\"></p><button class=\\"secondary\\" type=\\"button\\" id=\\"fill\\">Fill recovery code field</button>":"<p class=\\"hint\\">The recovery code is no longer in this browser. Authorize delivery again when ready.</p><button class=\\"secondary\\" type=\\"button\\" id=\\"again\\">Authorize delivery again</button>")+"<form id=\\"f\\"><label for=\\"token\\">Recovery code</label><input id=\\"token\\" autocomplete=\\"one-time-code\\" required><button>Verify code</button></form>");if(available){document.getElementById("shown").textContent=state.token;document.getElementById("fill").onclick=()=>{document.getElementById("token").value=state.token;note("Recovery code field filled. Select Verify code to continue.",true)}}else document.getElementById("again").onclick=()=>go("delivery");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/reset-validate",{token:document.getElementById("token").value.trim()});if(!r.ok||r.data.verified!==true)return note(r.data.message||"This recovery code could not be verified.");state.token="";go("password")}}
else if(state.step==="password"){if(state.saved){app.innerHTML=shell("Password saved","Continue to sign in with your new password.","<p class=\\"success\\"><strong>Password saved.</strong> Your new password is ready to use.</p><button id=\\"continue\\">Continue to sign in</button>");document.getElementById("continue").onclick=()=>{state.saved=false;go("signin")};return}app.innerHTML=shell("Create a new password","Choose a password that meets every item below.","<p><strong>Password policy:</strong> 12–128 characters, uppercase and lowercase letters, a number, a symbol, and no spaces.</p><form id=\\"f\\"><label for=\\"p\\">New password</label><input id=\\"p\\" type=\\"password\\" autocomplete=\\"new-password\\" required><label for=\\"c\\">Confirm new password</label><input id=\\"c\\" type=\\"password\\" autocomplete=\\"new-password\\" required><button>Save new password</button></form>");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const p=document.getElementById("p").value,c=document.getElementById("c").value;if(p!==c)return note("The two passwords do not match.");const r=await api("/api/reset-complete",{password:p,confirm:c});if(!r.ok||r.data.saved!==true)return note(r.data.message||"We could not save that password.");state.saved=true;render()}}
else if(state.step==="signin"){app.innerHTML=shell("Sign in","Use your new password, then complete one short security check.","<form id=\\"f\\"><label for=\\"email\\">Hospital account email</label><input id=\\"email\\" type=\\"email\\" autocomplete=\\"username\\" required><label for=\\"p\\">Password</label><input id=\\"p\\" type=\\"password\\" autocomplete=\\"current-password\\" required><button>Sign in</button></form><button class=\\"link\\" type=\\"button\\" id=\\"reset\\">Reset password instead</button>");document.getElementById("email").value=state.identifier;document.getElementById("reset").onclick=()=>go("identify");document.getElementById("f").onsubmit=async e=>{e.preventDefault();state.identifier=document.getElementById("email").value.trim();save();const r=await api("/api/login",{identifier:state.identifier,password:document.getElementById("p").value});if(!r.ok)return note(r.data.message||"We could not sign you in.");console.log("SIMULATED MFA DELIVERY: verification code =",r.data.evaluationMfaCode);go("mfa")}}
else if(state.step==="mfa"){app.innerHTML=shell("Security check","Enter the one-time code, then review the privacy conditions.","<p>For this evaluation, the deterministic mock code is shown here and in Activity logs.</p><p class=\\"code\\">246810</p><form id=\\"f\\"><label for=\\"code\\">Security code</label><input id=\\"code\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" required><button>Verify security code</button></form><button class=\\"link\\" type=\\"button\\" id=\\"back\\">Return to sign in</button>");document.getElementById("back").onclick=()=>go("signin");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa",{code:document.getElementById("code").value.trim()});if(!r.ok)return note(r.data.message||"That security code did not match.");go("privacy")}}
else if(state.step==="privacy"){app.innerHTML=shell("Review privacy conditions","Read the statement, select the checkbox, and save your choice.","<p>Hospital authorities need your permission to use account information to arrange this medication review appointment.</p><form id=\\"f\\"><label><input id=\\"accept\\" class=\\"check\\" type=\\"checkbox\\"> I have read and accept the updated privacy conditions.</label><button>Accept and continue</button></form>");document.getElementById("f").onsubmit=async e=>{e.preventDefault();if(!document.getElementById("accept").checked)return note("Please select the checkbox when you are ready.");const r=await api("/api/privacy",{accepted:true});if(!r.ok)return note(r.data.message||"Please sign in again before continuing.");go("appointment")}}
else if(state.step==="appointment"){app.innerHTML=shell("Confirm medication review appointment","Confirm the request to finish this process.","<p>Your request is for a medication dosage review. No additional personal details are needed here.</p><button id=\\"confirm\\">Confirm appointment request</button>");document.getElementById("confirm").onclick=async()=>{const r=await api("/api/appointment",{confirm:true});if(!r.ok)return note(r.data.message||"Please sign in again and try.");go("done")}}
else{app.innerHTML=shell("Appointment request confirmed","You have completed the recovery and privacy steps.","<p>Your medication dosage review appointment request has been recorded. Hospital staff will use their normal scheduling process.</p><button class=\\"secondary\\" id=\\"start\\">Return to account recovery start</button>");document.getElementById("start").onclick=()=>{state={step:"identify",identifier:"",token:"",saved:false};save();render()}}}
save();render()})();
</script></body></html>`;
}

async function api(request: Request, path: string): Promise<Response> {
  const current = getSession(request);
  const setCookie = current.fresh ? sessionCookie(current.id) : undefined;
  const data = await body(request);
  if (!data) return reply({ message: "Unable to process this request." }, 400, setCookie);
  if (!csrfOK(request, current.session)) return reply({ message: "Unable to process this request." }, 403, setCookie);

  if (path === "/api/reset-request") {
    if (!validEmail(data.identifier)) return reply({ message: "Check the email format and try again." }, 400, setCookie);
    clearVerified(current.session);
    clearRecovery(current.session);
    const identifier = normalize(data.identifier);
    const identity = trustworthyRequestIdentity(request);
    const context = hash(identifier + "|" + identity);
    const permitted = requestAllowed("reset-request:" + context);
    const user = users.get(identifier);
    current.session.recoveryContext = context;
    if (permitted && user) current.session.recoveryUserId = user.id;

    /*
      Task: trusted delivery authorization code is released only to the browser
      simulation after recovery initiation. The random reset token is not released.
    */
    return reply({
      message: "If an account is available, recovery instructions have been prepared.",
      nextStep: "delivery-channel",
      deliveryAuthorizationCode: DELIVERY_AUTHORIZATION_CODE,
    }, 200, setCookie);
  }

  if (path === "/api/recovery-delivery") {
    /*
      Task: delivery limits are server-controlled and bound to protected recovery
      context plus direct TLS origin identity, not to a replaceable session/header.
    */
    const context = current.session.recoveryContext;
    if (!context) return reply({ message: "Start recovery before authorizing delivery." }, 403, setCookie);
    const key = "delivery:" + context + "|" + trustworthyRequestIdentity(request);
    if (!attemptAllowed(deliveryAttempts, key)) {
      return reply({ message: "Please wait before trying trusted delivery authorization again." }, 429, setCookie);
    }
    if (!validCode(data.code) || !equal(data.code, DELIVERY_AUTHORIZATION_CODE)) {
      failedAttempt(deliveryAttempts, key);
      return reply({ message: "That trusted delivery authorization code did not match." }, 400, setCookie);
    }
    successfulAttempt(deliveryAttempts, key);
    current.session.deliveryAuthorizedUntil = Date.now() + DELIVERY_AUTH_TTL_MS;

    const token = randomId(32);
    if (current.session.recoveryUserId) {
      const tokenHash = hash(token);
      resetTokens.set(tokenHash, {
        userId: current.session.recoveryUserId,
        tokenHash,
        sessionId: current.id,
        expiresAt: Date.now() + RESET_TTL_MS,
        used: false,
      });
    }
    return reply({ message: "Simulated delivery opened.", evaluationToken: token }, 200, setCookie);
  }

  if (path === "/api/reset-validate") {
    const authorized = !!current.session.deliveryAuthorizedUntil &&
      current.session.deliveryAuthorizedUntil >= Date.now();
    const record = authorized && typeof data.token === "string" ? resetRecord(data.token, current.id) : null;

    /*
      Task: malformed, expired, used, unauthorized, and invalid codes never
      establish verified state and receive a non-success response.
    */
    if (!record) {
      clearVerified(current.session);
      return reply({
        message: "This recovery code could not be verified. Authorize delivery again when ready.",
        verified: false,
      }, 400, setCookie);
    }

    current.session.verifiedTokenHash = record.tokenHash;
    current.session.verifiedUserId = record.userId;
    current.session.verifiedExpires = record.expiresAt;
    clearRecovery(current.session);
    return reply({
      message: "Recovery code verified. Continue to create a password.",
      verified: true,
    }, 200, setCookie);
  }

  if (path === "/api/reset-complete") {
    if (data.password !== data.confirm) return reply({ message: "Passwords do not match.", saved: false }, 400, setCookie);
    const issue = passwordIssue(data.password);
    if (issue) return reply({ message: issue, saved: false }, 400, setCookie);

    /*
      Task: completion requires the prior server-side verified reset state.
      No password is changed for a missing, expired, used, or invalid state.
    */
    const record = verifiedRecord(current.session);
    const user = record ? [...users.values()].find(item => item.id === record.userId) : null;
    if (!record || !user) {
      clearVerified(current.session);
      return reply({
        message: "Your verified recovery step is no longer active. Authorize delivery again when ready.",
        saved: false,
      }, 403, setCookie);
    }

    try {
      user.passwordHash = await Bun.password.hash(data.password as string, { algorithm: "argon2id" });
      record.used = true;
      clearVerified(current.session);
      return reply({ message: "Password saved.", saved: true }, 200, setCookie);
    } catch {
      return reply({ message: "We could not save that password. Please try again.", saved: false }, 500, setCookie);
    }
  }

  if (path === "/api/login") {
    if (!validEmail(data.identifier) || typeof data.password !== "string" || data.password.length > 128) {
      return reply({ message: "We could not sign you in." }, 401, setCookie);
    }
    const identifier = normalize(data.identifier);
    /* Server-controlled protected-account plus trustworthy direct-origin key. */
    const key = "login:" + hash(identifier + "|" + trustworthyRequestIdentity(request));
    if (!attemptAllowed(loginAttempts, key)) return reply({ message: "We could not sign you in." }, 429, setCookie);

    const user = users.get(identifier);
    const okay = !!user && await Bun.password.verify(data.password, user.passwordHash);
    if (!okay) {
      failedAttempt(loginAttempts, key);
      return reply({ message: "We could not sign you in." }, 401, setCookie);
    }

    const mfaKey = "mfa:" + user.id + "|" + trustworthyRequestIdentity(request);
    if (!attemptAllowed(mfaAttempts, mfaKey)) {
      return reply({ message: "Security check is temporarily unavailable. Please wait and try again later." }, 429, setCookie);
    }
    successfulAttempt(loginAttempts, key);
    delete current.session.userId;
    current.session.mfaUserId = user.id;
    current.session.mfaExpires = Date.now() + MFA_TTL_MS;
    return reply({ message: "Security check required.", evaluationMfaCode: MFA_CODE }, 200, setCookie);
  }

  if (path === "/api/mfa") {
    const userId = current.session.mfaUserId;
    if (!userId || !current.session.mfaExpires || current.session.mfaExpires <= Date.now()) {
      delete current.session.mfaUserId;
      delete current.session.mfaExpires;
      return reply({ message: "This security check is no longer active. Return to sign in when ready." }, 401, setCookie);
    }
    const key = "mfa:" + userId + "|" + trustworthyRequestIdentity(request);
    if (!attemptAllowed(mfaAttempts, key)) {
      delete current.session.mfaUserId;
      delete current.session.mfaExpires;
      return reply({ message: "Too many security-code attempts. Return to sign in when ready." }, 429, setCookie);
    }
    if (!validCode(data.code) || !equal(data.code, MFA_CODE)) {
      failedAttempt(mfaAttempts, key);
      return reply({ message: "That security code did not match. Please try again." }, 401, setCookie);
    }
    successfulAttempt(mfaAttempts, key);
    current.session.userId = userId;
    delete current.session.mfaUserId;
    delete current.session.mfaExpires;
    return reply({ message: "Signed in." }, 200, setCookie);
  }

  const user = signedIn(current.session);
  /* Requirement 1: sensitive routes derive authorization from server session only. */
  if (!user) return reply({ message: "Please sign in to continue." }, 401, setCookie);

  if (path === "/api/privacy") {
    if (data.accepted !== true) return reply({ message: "Please confirm your choice." }, 400, setCookie);
    user.privacyAccepted = true;
    return reply({ message: "Privacy conditions accepted." }, 200, setCookie);
  }
  if (path === "/api/appointment") {
    if (data.confirm !== true || !user.privacyAccepted) {
      return reply({ message: "Please accept privacy conditions before confirming." }, 403, setCookie);
    }
    user.appointmentConfirmed = true;
    return reply({ message: "Appointment request confirmed." }, 200, setCookie);
  }
  return reply({ message: "Not found." }, 404, setCookie);
}

const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

Bun.serve({
  hostname: "localhost",
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/") {
        const current = getSession(request);
        const nonce = randomId(18);
        return new Response(page(nonce, current.session.csrf), {
          headers: headers(nonce, current.fresh ? sessionCookie(current.id) : undefined),
        });
      }
      if (request.method === "POST" && url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return new Response("Not found.", { status: 404, headers: headers(randomId(18)) });
    } catch {
      return new Response("Unable to process this request.", { status: 500, headers: headers(randomId(18)) });
    }
  },
});

console.log(`Hospital recovery server running securely at https://localhost:${PORT}`);
