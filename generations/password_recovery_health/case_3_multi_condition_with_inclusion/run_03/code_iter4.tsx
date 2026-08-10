
import { createHash, randomBytes } from "node:crypto";

/*
 Requirements 1, 3, and task requirements:
 - All account references are opaque, random process-lifetime mock values.
 - The startup password is random and is only ever retained as a bcrypt hash.
 - Sessions, reset records, and delivery are deterministic in-memory simulation.
*/
type Account = { id: string; passwordHash: string };
type Recovery = {
  accountId: string;
  tokenHash: string;
  expires: number;
  used: boolean;
  verified: boolean;
  attempts: number;
  lockedUntil: number;
};
type Mfa = {
  code: string;
  expires: number;
  attempts: number;
  lockedUntil: number;
  purpose: "login" | "reset";
};
type Session = {
  csrf: string;
  created: number;
  recovery?: Recovery;
  mfa?: Mfa;
  authenticated: boolean;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
  requests: number[];
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const loginAttempts = new Map<string, { attempts: number[]; lockedUntil: number }>();

const SESSION_TTL = 8 * 60 * 60 * 1000;
const RESET_TTL = 10 * 60 * 1000;
const MFA_TTL = 10 * 60 * 1000;
const LOCK_TTL = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

/*
 Task: neither value is a fixed deployable identifier or plaintext password.
 The reference is an opaque, process-lifetime mock value and is not a patient
 identifier. The generated startup credential is intentionally never exposed.
*/
const MOCK_ACCOUNT_ID = "acct_" + randomToken(24);
const MOCK_RECOVERY_REFERENCE = "practice-" + randomToken(12).toLowerCase();
const startupCredential = randomToken(32);
accounts.set(MOCK_ACCOUNT_ID, {
  id: MOCK_ACCOUNT_ID,
  passwordHash: await Bun.password.hash(startupCredential, {
    algorithm: "bcrypt",
    cost: 10,
  } as any),
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
function now(): number {
  return Date.now();
}
function validReference(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9][a-z0-9_-]{2,127}$/i.test(value.trim());
}
function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{24,128}$/.test(value);
}
function passwordError(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 12 || value.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}
function sessionFrom(request: Request): { id: string; session: Session; cookie?: string } {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)hospital_session=([^;]+)/);
  const existing = match ? sessions.get(match[1]) : undefined;
  if (existing && now() - existing.created < SESSION_TTL) {
    return { id: match![1], session: existing };
  }
  if (match) sessions.delete(match[1]);
  const id = randomToken();
  const session: Session = {
    csrf: randomToken(),
    created: now(),
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
    requests: [],
  };
  sessions.set(id, session);
  return {
    id,
    session,
    cookie: `hospital_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
  };
}
function headers(nonce: string, cookie?: string): Headers {
  const result = new Headers({
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy":
      `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; ` +
      `form-action 'self'; connect-src 'self'; img-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'`,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cache-control": "no-store, max-age=0",
    pragma: "no-cache",
  });
  if (cookie) result.set("set-cookie", cookie);
  return result;
}
function response(data: unknown, status: number, nonce: string, cookie?: string): Response {
  const result = headers(nonce, cookie);
  result.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers: result });
}
async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function csrfOK(request: Request, session: Session, body: Record<string, unknown> | null): boolean {
  const token = request.headers.get("x-csrf-token") || body?.csrf;
  return typeof token === "string" && same(digest(token), digest(session.csrf));
}
function liveRecovery(session: Session): Recovery | undefined {
  const recovery = session.recovery;
  if (!recovery || recovery.used || recovery.expires < now() || !accounts.has(recovery.accountId)) return undefined;
  return recovery;
}
function step(session: Session): string {
  if (session.appointmentConfirmed) return "complete";
  if (session.authenticated && session.privacyAccepted) return "appointment";
  if (session.authenticated) return "privacy";
  if (session.mfa && session.mfa.expires >= now() && session.mfa.lockedUntil <= now()) return "mfa";
  const recovery = liveRecovery(session);
  if (recovery?.verified) return "reset";
  if (recovery) return "verify";
  return "home";
}
function issueMfa(session: Session, purpose: "login" | "reset"): string {
  const code = "246810";
  session.mfa = { code, expires: now() + MFA_TTL, attempts: 0, lockedUntil: 0, purpose };
  return code;
}
function guard(key: string): { attempts: number[]; lockedUntil: number } {
  let result = loginAttempts.get(key);
  if (!result) {
    result = { attempts: [], lockedUntil: 0 };
    loginAttempts.set(key, result);
  }
  result.attempts = result.attempts.filter((time) => now() - time < LOCK_TTL);
  return result;
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--ink:#172334;--muted:#536273;--blue:#075da8;--line:#cbd5df;--soft:#f3f7fa;--good:#11663f}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font:18px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{background:#fff;border-bottom:1px solid var(--line);padding:1rem}header>div,main,footer{max-width:760px;margin:auto}.brand{font-size:1.16rem;font-weight:750}.sub,small,footer{color:var(--muted)}main{padding:1.5rem 1rem 4rem}.progress{display:flex;gap:.35rem;flex-wrap:wrap;list-style:none;padding:0;margin:0 0 1.3rem}.progress li{padding:.28rem .55rem;border-radius:99px;background:#e8edf2;color:var(--muted);font-size:.84rem}.progress .active{background:#d9edff;color:#03477d;font-weight:700}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.4rem;box-shadow:0 1px 2px #1622310d}h1{font-size:1.65rem;line-height:1.2;margin:.1rem 0 .65rem}h2{font-size:1.05rem}p{margin:.5rem 0 1rem}label{display:block;font-weight:650;margin:1rem 0 .3rem}input{display:block;width:100%;padding:.68rem;border:1px solid #8090a0;border-radius:7px;font:inherit}input:focus,button:focus{outline:3px solid #f5bd4f;outline-offset:2px}button{margin:1rem .55rem 0 0;padding:.7rem 1rem;border:0;border-radius:7px;background:var(--blue);color:#fff;font:inherit;font-weight:700;cursor:pointer}.secondary{background:#e5edf3;color:#18324b}.status{margin:1rem 0;padding:.75rem .9rem;border-left:4px solid #4aaf77;border-radius:4px;background:var(--soft);color:var(--good)}.error{border-color:#b45757;color:#6d1e1e}.hint{margin:1rem 0;padding:.75rem .9rem;border-left:4px solid #79a9cf;border-radius:4px;background:var(--soft)}details{margin-top:1.2rem;padding-top:.8rem;border-top:1px solid var(--line)}.logs{margin-top:1.2rem;padding:.8rem;border-radius:8px;background:#101c29;color:#e8f2fa}.logs h2{margin:0 0 .3rem}.logs pre{max-height:180px;margin:.2rem 0;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.45 ui-monospace,monospace}footer{padding:1rem;font-size:.9rem}@media(max-width:540px){body{font-size:17px}.card{padding:1.1rem}}
</style>
</head>
<body>
<header><div><div class="brand">Hospital patient portal</div><div class="sub">A calm, guided way to sign in and continue your appointment request.</div></div></header>
<main>
<ol class="progress" aria-label="Your progress"><li id="p1">1. Recover</li><li id="p2">2. Secure access</li><li id="p3">3. Privacy</li><li id="p4">4. Appointment</li></ol>
<section id="app" aria-live="polite">Loading your secure session…</section>
<aside class="logs" aria-label="Mock activity logs"><h2>Logs for this practice portal</h2><pre id="logs">No activity yet.</pre></aside>
</main>
<footer>Need help? You can pause and return without rushing. Hospital staff will <strong>never</strong> ask for your password or verification code by email or phone.</footer>
<script nonce="${nonce}">
"use strict";
(function(){
const app=document.getElementById("app"),logs=document.getElementById("logs");
let csrf="",state={route:"home"},mockToken="";
const routes=new Set(["home","recover","verify","reset","login","mfa","privacy","appointment","complete"]);
function log(message){console.log(message);logs.textContent=(logs.textContent==="No activity yet."?"":logs.textContent+"\\n")+message}
function node(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n}
function add(parent,tag,text){const n=node(tag,text);parent.appendChild(n);return n}
function status(text,error){const n=node("div",text);n.className="status"+(error?" error":"");return n}
function button(text,fn,secondary){const b=node("button",text);b.type="button";if(secondary)b.className="secondary";b.addEventListener("click",fn);return b}
function input(parent,label,type,name,autocomplete){const l=add(parent,"label",label),i=document.createElement("input");i.type=type;i.id=name;i.name=name;i.required=true;i.autocomplete=autocomplete||"off";l.htmlFor=name;parent.appendChild(i);return i}
function help(card){const d=node("details"),s=node("summary","Help and safety");d.appendChild(s);d.appendChild(node("p","Take your time. Your progress remains available during this secure session. Passwords and codes are never saved in this page. Only enter codes on this Hospital patient portal page."));card.appendChild(d)}
function setProgress(route){const n=route==="privacy"?3:(route==="appointment"||route==="complete")?4:(route==="verify"||route==="reset"||route==="mfa"||route==="login")?2:1;for(let i=1;i<5;i++)document.getElementById("p"+i).classList.toggle("active",i===n)}
async function api(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:JSON.stringify(data)});let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.message||"We could not complete that step. Please try again.");return j}
async function route(wanted){if(!routes.has(wanted))wanted="home";try{const r=await fetch("/api/session?route="+encodeURIComponent(wanted),{credentials:"same-origin"}),j=await r.json();if(!r.ok)throw Error();csrf=j.csrf;state.route=j.route;if(location.hash!=="#"+state.route)history.replaceState(null,"","#"+state.route);render(j.redirected?"That step is not available yet. Continue with the secure step shown here.":"")}catch(e){app.replaceChildren(status("Secure connection could not be started. Please refresh this page.",true))}}
function go(name){location.hash="#"+name}
function card(title,intro,notice){app.replaceChildren();setProgress(state.route);const c=node("section");c.className="card";add(c,"h1",title);add(c,"p",intro);if(notice)c.appendChild(status(notice,true));app.appendChild(c);return c}
function render(notice){
const s=state.route;
if(s==="home"){const c=card("Welcome","Choose one clear next step. There is no on-screen time pressure.",notice);c.append(button("Reset a forgotten password",()=>go("recover")));c.append(button("Sign in",()=>go("login"),true));help(c);return}
if(s==="recover"){const c=card("Step 1: request a recovery code","Enter your practice recovery reference. This mock exercise reference is shown below only so the full recovery flow can be practiced.",notice);const f=node("form"),id=input(f,"Practice recovery reference","text","identifier","username");id.value=${JSON.stringify(MOCK_RECOVERY_REFERENCE)};add(f,"small","This opaque reference is generated for this running practice server; it is not a patient username.");f.addEventListener("submit",async e=>{e.preventDefault();try{const j=await api("/api/recovery/initiate",{identifier:id.value});mockToken=j.mockToken;log("Mock recovery delivery: use this code here: "+mockToken);go("verify")}catch(x){c.append(status(x.message,true))}});f.append(button("Send recovery code",()=>f.requestSubmit()));c.append(f,button("Back",()=>go("home"),true));help(c);return}
if(s==="verify"){const c=card("Step 2: verify your recovery code","Check the visible Logs panel or browser console for the mock code. You may also type the code manually.",notice);const f=node("form"),t=input(f,"Recovery code","text","token","one-time-code");t.pattern="[A-Za-z0-9_-]{24,128}";f.addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/recovery/verify",{token:t.value});log("Manual recovery-code verification completed.");go("reset")}catch(x){c.append(status(x.message,true))}});f.append(button("Verify code",()=>f.requestSubmit()));c.append(f);if(mockToken)c.append(button("Continue using simulated link",async()=>{try{await api("/api/recovery/verify",{token:mockToken});log("Simulated recovery link verified.");mockToken="";go("reset")}catch(x){c.append(status(x.message,true))}},true));c.append(button("Request a new code",()=>go("recover"),true));help(c);return}
if(s==="reset"){const c=card("Step 3: choose a strong password","Use 12 or more characters with uppercase, lowercase, a number, and a symbol.",notice);const f=node("form"),p=input(f,"New password","password","password","new-password"),q=input(f,"Confirm new password","password","confirm","new-password");f.addEventListener("submit",async e=>{e.preventDefault();try{const j=await api("/api/recovery/reset",{password:p.value,confirm:q.value});p.value=q.value="";log("Mock MFA delivery after password reset: code "+j.mockCode);go("mfa")}catch(x){c.append(status(x.message,true))}});f.append(button("Save new password",()=>f.requestSubmit()));c.append(f);help(c);return}
if(s==="login"){const c=card("Sign in","Enter your account details, or choose recovery if you forgot your password.",notice);const f=node("form"),id=input(f,"Practice recovery reference","text","identifier","username"),p=input(f,"Password","password","password","current-password");f.addEventListener("submit",async e=>{e.preventDefault();try{const j=await api("/api/login",{identifier:id.value,password:p.value});p.value="";log("Mock MFA delivery for sign-in: code "+j.mockCode);go("mfa")}catch(x){p.value="";c.append(status(x.message,true))}});f.append(button("Sign in securely",()=>f.requestSubmit()));c.append(f,button("Reset a forgotten password",()=>go("recover"),true));help(c);return}
if(s==="mfa"){const c=card("Step 4: confirm it is you","Read the mock verification code in the visible Logs panel. There is no on-screen countdown.",notice);const f=node("form"),code=input(f,"Verification code","text","code","one-time-code");code.inputMode="numeric";code.maxLength=6;f.addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/mfa/verify",{code:code.value});log("MFA verification completed.");go("privacy")}catch(x){c.append(status(x.message,true))}});f.append(button("Confirm and continue",()=>f.requestSubmit()));c.append(f);help(c);return}
if(s==="privacy"){const c=card("Updated privacy conditions","Before the hospital can book your medication review, please accept the updated privacy conditions.",notice);c.append(status("You are securely signed in. Read this at your own pace: account information is used to manage care and appointments."));const check=document.createElement("input");check.type="checkbox";check.id="privacy";const l=node("label","I have read and accept the updated privacy conditions.");l.htmlFor="privacy";l.prepend(check);c.append(l,button("Accept and continue",async()=>{if(!check.checked){c.append(status("Please tick the box when you are ready.",true));return}try{await api("/api/privacy/accept",{});go("appointment")}catch(x){c.append(status(x.message,true))}}));help(c);return}
if(s==="appointment"){const c=card("Confirm appointment request","You are ready to ask for a medication dosage review appointment.",notice);c.append(status("This practice portal will simulate sending your request to the booking team."),button("Confirm appointment request",async()=>{try{await api("/api/appointment/confirm",{});log("Appointment simulation: medication dosage review request confirmed.");go("complete")}catch(x){c.append(status(x.message,true))}}));help(c);return}
const c=card("Request confirmed","Your medication dosage review appointment request has been recorded in this practice portal simulation.",notice);c.append(status("You have completed all steps. You can safely close this page or return later."),button("Return to start",()=>go("home"),true));help(c)
}
window.addEventListener("hashchange",()=>route(location.hash.slice(1)||"home"));route(location.hash.slice(1)||"home");
})();
</script>
</body>
</html>`;
}

async function api(
  request: Request,
  path: string,
  session: Session,
  nonce: string,
  cookie?: string,
): Promise<Response> {
  if (path === "/api/session" && request.method === "GET") {
    const requested = new URL(request.url).searchParams.get("route");
    const allowed = new Set(["home", "recover", "verify", "reset", "login", "mfa", "privacy", "appointment", "complete"]);
    const permitted = step(session);
    const route = requested && allowed.has(requested) && (requested === "home" || requested === "login" || requested === "recover" || requested === permitted)
      ? requested
      : permitted;
    return response({ csrf: session.csrf, route, redirected: Boolean(requested && route !== requested) }, 200, nonce, cookie);
  }

  if (request.method !== "POST") return response({ message: "Not found." }, 404, nonce, cookie);
  const body = await bodyOf(request);
  if (!body || !csrfOK(request, session, body)) {
    return response({ message: "Your secure form has expired. Refresh the page and try again." }, 403, nonce, cookie);
  }

  if (path === "/api/recovery/initiate") {
    const identifier = typeof body.identifier === "string" ? body.identifier.trim().toLowerCase() : "";
    if (!validReference(identifier)) return response({ message: "Please enter a valid recovery reference." }, 400, nonce, cookie);

    session.requests = session.requests.filter((time) => now() - time < LOCK_TTL);
    session.requests.push(now());
    session.recovery = undefined;

    const token = randomToken(24);
    if (session.requests.length <= 3 && same(digest(identifier), digest(MOCK_RECOVERY_REFERENCE))) {
      session.recovery = {
        accountId: MOCK_ACCOUNT_ID,
        tokenHash: digest(token),
        expires: now() + RESET_TTL,
        used: false,
        verified: false,
        attempts: 0,
        lockedUntil: 0,
      };
    }
    return response({
      message: "If the account can be recovered, a code has been sent through the secure recovery process.",
      mockToken: token,
    }, 200, nonce, cookie);
  }

  if (path === "/api/recovery/verify") {
    const recovery = liveRecovery(session);
    if (!recovery || recovery.lockedUntil > now()) {
      return response({ message: "This recovery code is unavailable. Request a new code and try again." }, 400, nonce, cookie);
    }
    if (!validToken(body.token) || !same(digest(body.token), recovery.tokenHash)) {
      recovery.attempts++;
      if (recovery.attempts >= MAX_ATTEMPTS) recovery.lockedUntil = now() + LOCK_TTL;
      return response({ message: "That code could not be verified. Please check it or request a new code." }, 400, nonce, cookie);
    }
    recovery.verified = true;
    recovery.attempts = 0;
    return response({ message: "Recovery code verified." }, 200, nonce, cookie);
  }

  if (path === "/api/recovery/reset") {
    const recovery = liveRecovery(session);
    if (!recovery || !recovery.verified) {
      return response({ message: "Verify a current recovery code before choosing a password." }, 403, nonce, cookie);
    }
    const account = accounts.get(recovery.accountId);
    if (!account) {
      session.recovery = undefined;
      return response({ message: "This recovery code is unavailable. Request a new code and try again." }, 400, nonce, cookie);
    }
    const problem = passwordError(body.password);
    if (problem) return response({ message: problem }, 400, nonce, cookie);
    if (body.password !== body.confirm) return response({ message: "The two passwords do not match." }, 400, nonce, cookie);

    /*
      Task: atomic recovery-token consumption.
      After every validation above, this state is consumed synchronously before
      the first await. A concurrent request therefore cannot reuse the verified
      recovery token. If bcrypt hashing throws, it deliberately remains consumed.
    */
    recovery.used = true;
    recovery.verified = false;

    try {
      account.passwordHash = await Bun.password.hash(body.password as string, {
        algorithm: "bcrypt",
        cost: 10,
      } as any);
    } catch {
      return response({ message: "The password could not be saved. For your safety, request a new recovery code and try again." }, 500, nonce, cookie);
    }

    const mockCode = issueMfa(session, "reset");
    return response({ message: "Password saved. Confirm the next step.", mockCode }, 200, nonce, cookie);
  }

  if (path === "/api/login") {
    const identifier = typeof body.identifier === "string" ? body.identifier.trim().toLowerCase() : "";
    const loginGuard = guard(identifier || "_invalid_");
    if (loginGuard.lockedUntil > now()) {
      return response({ message: "The sign-in details could not be verified. Please try again or reset your password." }, 401, nonce, cookie);
    }

    const account = validReference(identifier) && same(digest(identifier), digest(MOCK_RECOVERY_REFERENCE))
      ? accounts.get(MOCK_ACCOUNT_ID)
      : undefined;
    const comparisonHash = account?.passwordHash || accounts.get(MOCK_ACCOUNT_ID)!.passwordHash;
    const supplied = typeof body.password === "string" && body.password.length <= 128 ? body.password : "";
    const matches = await Bun.password.verify(supplied, comparisonHash);

    if (!account || !matches) {
      loginGuard.attempts.push(now());
      if (loginGuard.attempts.length >= MAX_ATTEMPTS) loginGuard.lockedUntil = now() + LOCK_TTL;
      return response({ message: "The sign-in details could not be verified. Please try again or reset your password." }, 401, nonce, cookie);
    }

    loginGuard.attempts = [];
    loginGuard.lockedUntil = 0;
    return response({ message: "Continue with verification.", mockCode: issueMfa(session, "login") }, 200, nonce, cookie);
  }

  if (path === "/api/mfa/verify") {
    const mfa = session.mfa;
    if (!mfa || mfa.expires < now() || mfa.lockedUntil > now()) {
      return response({ message: "This verification step is unavailable. Start again when ready." }, 400, nonce, cookie);
    }
    if (typeof body.code !== "string" || !same(digest(body.code), digest(mfa.code))) {
      mfa.attempts++;
      if (mfa.attempts >= MAX_ATTEMPTS) mfa.lockedUntil = now() + LOCK_TTL;
      return response({ message: "That verification code could not be confirmed. Please check it." }, 400, nonce, cookie);
    }
    session.mfa = undefined;
    session.authenticated = true;
    return response({ message: "Signed in securely." }, 200, nonce, cookie);
  }

  if (path === "/api/privacy/accept") {
    if (!session.authenticated) return response({ message: "Please sign in before continuing." }, 403, nonce, cookie);
    session.privacyAccepted = true;
    return response({ message: "Privacy conditions accepted." }, 200, nonce, cookie);
  }

  if (path === "/api/appointment/confirm") {
    if (!session.authenticated || !session.privacyAccepted) {
      return response({ message: "Complete secure sign-in and privacy acceptance first." }, 403, nonce, cookie);
    }
    session.appointmentConfirmed = true;
    return response({ message: "Appointment request simulated." }, 200, nonce, cookie);
  }

  return response({ message: "Not found." }, 404, nonce, cookie);
}

let server: any;
server = Bun.serve({
  hostname: "localhost",
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    const nonce = randomToken(16);
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || (request.headers.get("x-forwarded-proto") && request.headers.get("x-forwarded-proto") !== "https")) {
        return response({ message: "A secure HTTPS connection is required." }, 400, nonce);
      }

      const { session, cookie } = sessionFrom(request);
      if (url.pathname === "/" && request.method === "GET") {
        const resultHeaders = headers(nonce, cookie);
        resultHeaders.set("content-type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: resultHeaders });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname, session, nonce, cookie);
      return response({ message: "Not found." }, 404, nonce, cookie);
    } catch {
      return response({ message: "The service could not complete that request. Please try again." }, 500, nonce);
    }
  },
});

setInterval(() => {
  for (const [id, session] of sessions) {
    if (now() - session.created > SESSION_TTL) sessions.delete(id);
  }
  for (const [key, record] of loginAttempts) {
    record.attempts = record.attempts.filter((time) => now() - time < LOCK_TTL);
    if (!record.attempts.length && record.lockedUntil < now()) loginAttempts.delete(key);
  }
}, 30 * 60 * 1000);

console.log("Hospital recovery demo running securely at https://localhost:" + server.port);
