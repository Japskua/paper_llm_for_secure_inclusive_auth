
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

/*
 Password Recovery System — Bun HTTPS server and inline vanilla-JS SPA.
 [1] Access control / CSRF   [2] XSS prevention   [3] secure configuration
 [4] Authentication / MFA    [5] anti-phishing guidance
*/

type Stage =
  | "anonymous"
  | "channel"
  | "recovery"
  | "verified"
  | "resetComplete"
  | "mfa"
  | "authenticated";

type Session = {
  id: string;
  csrf: string;
  stage: Stage;
  createdAt: number;
  userId?: string;
  channelHash?: string;
  resetHash?: string;
  resetExpires?: number;
  resetUsed?: boolean;
  mfaCode?: string;
  mfaAttempts: number;
  privacyAccepted?: boolean;
};

const sessions = new Map<string, Session>();
const loginFailures = new Map<string, { failures: number; lockedUntil: number }>();

// [4] Opaque account data stays server-side. This is a precomputed Argon2id PHC hash;
// no plaintext initial password exists anywhere in this file.
const INTERNAL_ACCOUNT = {
  id: "account-1",
  login: "helena.patient@hospital.test",
  passwordHash:
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRmb3Jtb2NrMTI$VYqXJcKzPzx2CJCPHcGXN6YPgOxWrG1HQzNl0lhy8SQ",
};

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_TTL = 24 * 60 * 60 * 1000;
const RESET_TTL = 15 * 60 * 1000;
const APPROVED_CHANNEL_CODE = "135790"; // deterministic mock confirmation fixture
const MFA_CODE = "246810"; // deterministic mock MFA fixture

function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}
function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}
function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}
function getSession(request: Request) {
  const id = parseCookies(request).recovery_session;
  if (!id || !/^[A-Za-z0-9_-]{30,90}$/.test(id)) return undefined;
  const session = sessions.get(id);
  if (!session || Date.now() - session.createdAt > SESSION_TTL) {
    sessions.delete(id);
    return undefined;
  }
  return session;
}
function createSession() {
  const session: Session = {
    id: randomToken(),
    csrf: randomToken(),
    stage: "anonymous",
    createdAt: Date.now(),
    mfaAttempts: 0,
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(session: Session) {
  return `recovery_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}
function baseHeaders(nonce?: string) {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, private, max-age=0",
    Pragma: "no-cache",
  });
  if (nonce) {
    headers.set(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`
    );
  }
  return headers;
}
function json(body: Record<string, unknown>, status = 200, cookie?: string) {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}
function genericError(status = 400) {
  return json(
    { ok: false, message: "We could not complete that step. Please check the information and try again." },
    status
  );
}
function validSameOrigin(request: Request) {
  try {
    return !!request.headers.get("origin") &&
      request.headers.get("origin") === new URL(request.url).origin;
  } catch {
    return false;
  }
}
function csrfSession(request: Request) {
  const session = getSession(request);
  const csrf = request.headers.get("x-csrf-token") || "";
  if (!session || !validSameOrigin(request) || !safeEqual(session.csrf, csrf)) return undefined;
  return session;
}
function isAllowedEmail(value: unknown) {
  return typeof value === "string" &&
    value.length <= 160 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(value);
}
function isToken(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{40,100}$/.test(value);
}
function passwordProblem(password: unknown) {
  if (typeof password !== "string") return "Enter a new password.";
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 200) return "Please use 200 characters or fewer.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/\d/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9\s]/.test(password)) return "Include a symbol.";
  if (/\s/.test(password)) return "Do not use spaces.";
  return "";
}
async function requestData(request: Request) {
  if (Number(request.headers.get("content-length") || "0") > 10_000) throw new Error("oversized");
  return await request.json() as Record<string, unknown>;
}

/* Expired recovery material is invalidated centrally and never restored by the client. */
function expireRecoveryIfNeeded(session: Session) {
  if ((session.stage === "recovery" || session.stage === "verified") &&
    (!session.resetExpires || Date.now() > session.resetExpires || session.resetUsed)) {
    session.stage = "anonymous";
    session.userId = undefined;
    session.resetHash = undefined;
    session.resetExpires = undefined;
    session.resetUsed = true;
    return true;
  }
  return false;
}
function recoveryStateError(session: Session) {
  expireRecoveryIfNeeded(session);
  return json({
    ok: false,
    invalidRecovery: true,
    message: "This recovery step is no longer available. Start recovery again when you are ready.",
  });
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Care Portal – Password recovery</title>
<style nonce="${nonce}">
:root{--ink:#193447;--muted:#5d6f7c;--blue:#075a8c;--blue2:#e9f5fb;--line:#c8d8e1;--good:#155d3a;--warn:#6f4c00;--paper:#fff;--bg:#f4f8fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.52 system-ui,-apple-system,"Segoe UI",sans-serif}a{color:#064f7b;font-weight:650}button,input{font:inherit}button{cursor:pointer;border-radius:8px;border:0;padding:.7rem 1.05rem;font-weight:750;background:var(--blue);color:#fff}button:hover{background:#03466d}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #e49a21;outline-offset:3px}.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:.5rem;z-index:3}.top{border-bottom:1px solid var(--line);background:#fff}.topin,main,footer{max-width:820px;margin:auto;padding-left:1.2rem;padding-right:1.2rem}.topin{padding-top:1rem;padding-bottom:1rem}.brand{font-size:1.25rem;font-weight:800}.tag{color:var(--muted);font-size:.94rem}.progress{padding:1rem 0;border-top:1px solid #e4edf1}.progress ol{list-style:none;display:flex;gap:.4rem;margin:0;padding:0;flex-wrap:wrap}.progress li{font-size:.88rem;border-radius:20px;padding:.25rem .65rem;background:#edf2f5;color:var(--muted)}.progress li.now{background:#ccecf9;color:#063e60;font-weight:800}.progress li.done{background:#d9f1df;color:var(--good)}main{padding-top:2rem;padding-bottom:1.2rem;min-height:61vh}.card{max-width:650px;background:var(--paper);padding:1.45rem;border:1px solid var(--line);border-radius:13px;box-shadow:0 2px 8px #123311}h1{font-size:1.7rem;line-height:1.25;margin:.1rem 0 .7rem}h2{font-size:1.15rem;margin:1.2rem 0 .4rem}p{margin:.55rem 0}.next{background:var(--blue2);border-left:5px solid var(--blue);padding:.8rem 1rem;margin:1rem 0}.notice{padding:.8rem 1rem;border-radius:8px;margin:1rem 0;background:#edf7ef;color:var(--good)}.warning{background:#fff7e4;color:var(--warn)}label{display:block;font-weight:750;margin-top:1rem}input{display:block;width:100%;padding:.65rem;border:2px solid #78909f;border-radius:7px;margin-top:.3rem}.hint,.quiet{font-size:.9rem;color:var(--muted)}.actions{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:1.2rem}.helpbox{margin-top:1.1rem;border-top:1px solid var(--line);padding-top:1rem}.logpanel{margin-top:1rem;background:#10232d;color:#d8edf5;border-radius:10px;padding:.8rem}.logpanel h2{margin:0 0 .4rem;font-size:1rem}.logs{white-space:pre-wrap;word-break:break-word;font:13px/1.4 ui-monospace,SFMono-Regular,monospace;max-height:150px;overflow:auto}footer{padding-bottom:2rem;color:var(--muted);font-size:.88rem}@media(max-width:500px){body{font-size:17px}.card{padding:1rem}.progress ol{display:grid;grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to the current step</a>
<header class="top"><div class="topin"><div class="brand">Care Portal</div><div class="tag">Private account recovery</div><nav class="progress" aria-label="Recovery progress"><ol id="progress"></ol></nav></div></header>
<main id="main" tabindex="-1"><div id="app" aria-live="polite">Preparing your private recovery space…</div></main>
<footer>Take your time. Your server-backed step is saved securely. <a href="#help" id="footer-help">Get help and safety advice</a></footer>
<script nonce="${nonce}">
(() => {
"use strict";
/* [2] Dynamic content uses DOM nodes and textContent only; no user data is inserted as HTML. */
const app=document.getElementById("app"),progress=document.getElementById("progress");
const storageKey="care-recovery-progress",tokenKey="care-recovery-token";
const steps=["1. Start","2. Approved channel","3. New password","4. Sign in","5. Privacy"];
let csrf="",current="start",message="",serverStage="anonymous",logs=[];
function cleanStored(){localStorage.removeItem(storageKey);sessionStorage.removeItem(tokenKey);}
function stageFor(view){return({start:"anonymous",channel:"channel",delivery:"recovery",verify:"recovery",password:"verified",success:"resetComplete",login:"resetComplete",mfa:"mfa",privacy:"authenticated",confirmed:"authenticated"})[view]||"anonymous";}
function save(){if(current!=="help")localStorage.setItem(storageKey,JSON.stringify({current:current,serverStage:stageFor(current),message:message}));}
function clear(n){while(n.firstChild)n.removeChild(n.firstChild);}
function el(tag,props,...children){const n=document.createElement(tag);for(const [k,v] of Object.entries(props||{})){if(k==="class")n.className=v;else if(k==="type")n.type=v;else if(k==="href")n.href=v;else if(k==="id")n.id=v;else if(k==="value")n.value=v;else if(k==="placeholder")n.placeholder=v;else if(k==="onclick")n.addEventListener("click",v);else n.setAttribute(k,String(v));}for(const c of children.flat()){if(c!==null&&c!==undefined)n.append(c.nodeType?c:document.createTextNode(String(c)));}return n;}
function card(title){return el("section",{class:"card","aria-labelledby":"page-title"},el("h1",{id:"page-title"},title));}
function p(text,cls){return el("p",cls?{class:cls}:{},text);}
function setMessage(text){message=text;save();}
function addLog(text){console.log(text);logs.push(text);}
function progressIndex(){return({start:0,channel:1,delivery:1,verify:1,password:2,success:3,login:3,mfa:3,privacy:4,confirmed:4,help:0})[current]||0;}
function renderProgress(){clear(progress);const at=progressIndex();steps.forEach((s,i)=>progress.append(el("li",{class:i===at?"now":i<at?"done":""},s)));}
function helpLink(){const a=el("a",{href:"#help"},"Help and safety advice");a.addEventListener("click",e=>{e.preventDefault();current="help";render();});return a;}
function tail(box){box.append(el("div",{class:"helpbox"},p("Need a pause? This browser can restore the matching server-backed step when you return.","quiet")));const q=el("p",{class:"quiet"},"Need support? ");q.append(helpLink());box.append(q);return box;}
function showMessage(box){if(message)box.append(el("div",{class:"notice"},message));}
function logPanel(){return el("aside",{class:"logpanel","aria-label":"Simulation logs"},el("h2",{},"Logs"),el("div",{class:"logs"},logs.length?logs.join("\\n"):"No simulated messages yet."));}
async function api(path,body){const r=await fetch(path,{method:body===undefined?"GET":"POST",credentials:"same-origin",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)});try{return await r.json();}catch{return {ok:false,message:"We could not complete that step."};}}
function invalidRecovery(data){if(!data.invalidRecovery)return false;cleanStored();serverStage="anonymous";current="start";message="This recovery step is no longer available. Start recovery again when you are ready.";render();return true;}
function button(text,fn,secondary){return el("button",{type:"button",class:secondary?"secondary":"",onclick:fn},text);}
async function bootstrap(){
 const boot=await api("/api/bootstrap");if(!boot.ok){message="Your private recovery space could not be prepared. Refresh and try again.";render();return;}
 csrf=boot.csrf;const status=await api("/api/status");serverStage=status.stage||"anonymous";
 const saved=(()=>{try{return JSON.parse(localStorage.getItem(storageKey)||"{}");}catch{return {};}})();
 if(status.recoveryExpired){cleanStored();message="This recovery link has expired. Start recovery again when you are ready.";current="start";}
 else if(saved.current&&saved.serverStage===serverStage){current=saved.current;message=saved.message||"";}
 else if(serverStage!=="anonymous"){current=({channel:"channel",recovery:"delivery",verified:"password",resetComplete:"success",mfa:"mfa",authenticated:status.privacyAccepted?"confirmed":"privacy"})[serverStage]||"start";message="Your saved step has been restored.";}
 const routeToken=new URLSearchParams(location.search).get("token");
 if(location.pathname==="/recovery/verify"&&routeToken&&/^[A-Za-z0-9_-]{40,100}$/.test(routeToken)&&serverStage==="recovery"){sessionStorage.setItem(tokenKey,routeToken);current="verify";message="Recovery link opened. Check the code below to continue.";}
 render();
}
function startView(){const b=card("Reset your password");b.append(p("We will guide you one small step at a time."),el("div",{class:"next"},el("strong",{},"Next step: "),"enter the email address you use for your account."));showMessage(b);const f=el("form",{}),i=el("input",{id:"email",type:"email",autocomplete:"email",required:"",maxlength:"160"});f.append(el("label",{for:"email"},"Account email"),i,p("For privacy, we give the same message whether or not an account can be recovered.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Continue")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/recovery/start",{email:i.value});if(!d.ok){setMessage(d.message);render();return;}serverStage="channel";current="channel";setMessage(d.message);render();});b.append(f);return tail(b);}
function channelView(){const b=card("Confirm your approved recovery channel");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"confirm access to your approved recovery channel before a reset code is created."));showMessage(b);b.append(p("This separate check protects you if somebody else knows your email address."),p("Mock approved-channel confirmation code for this demo: 135790.","hint"));const f=el("form",{}),i=el("input",{id:"channel-code",type:"text",autocomplete:"one-time-code",required:"",maxlength:"6"});f.append(el("label",{for:"channel-code"},"Approved-channel confirmation code"),i,el("div",{class:"actions"},el("button",{type:"submit"},"Confirm channel")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/recovery/channel",{code:i.value.trim()});if(!d.ok){setMessage(d.message);render();return;}serverStage="recovery";sessionStorage.setItem(tokenKey,d.token);addLog("SIMULATED RECOVERY DELIVERY: private reset code: "+d.token);addLog("SIMULATED RECOVERY DELIVERY: verification link: "+location.origin+"/recovery/verify?token="+d.token);current="delivery";setMessage("Approved channel confirmed. Your private recovery details are now in the Logs panel.");render();});b.append(f);return tail(b);}
function deliveryView(){const b=card("Check your recovery message");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"open the simulated recovery link, or enter the code yourself."));showMessage(b);b.append(p("The reset details were revealed only after the approved-channel check succeeded."));const t=sessionStorage.getItem(tokenKey);if(t&&/^[A-Za-z0-9_-]{40,100}$/.test(t))b.append(el("div",{class:"actions"},el("a",{href:"/recovery/verify?token="+encodeURIComponent(t)},"Open simulated recovery link")));b.append(el("div",{class:"actions"},button("Enter a code manually",()=>{current="verify";save();render();},true)));return tail(b);}
function verifyView(){const b=card("Check your recovery code");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"paste or type the private code, then select Check code."));showMessage(b);const f=el("form",{}),i=el("input",{id:"code",type:"text",autocomplete:"one-time-code",required:"",maxlength:"100",placeholder:"Recovery code"}),t=sessionStorage.getItem(tokenKey);if(t)i.value=t;f.append(el("label",{for:"code"},"Recovery code"),i,p("Codes are private. Never share a password or code with anyone who contacts you unexpectedly.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Check code")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/recovery/verify",{token:i.value.trim()});if(invalidRecovery(d))return;if(!d.ok){setMessage(d.message);render();return;}sessionStorage.setItem(tokenKey,i.value.trim());serverStage="verified";current="password";setMessage("Code checked. You can now choose a new password.");history.replaceState({},"","/");render();});b.append(f);return tail(b);}
function passwordView(){const b=card("Choose a new password");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"create your new password, then save it."));showMessage(b);b.append(el("h2",{},"Password checklist"),el("ul",{},el("li",{},"At least 12 characters"),el("li",{},"An uppercase and lowercase letter"),el("li",{},"A number and a symbol"),el("li",{},"No spaces")));const f=el("form",{}),a=el("input",{id:"new-password",type:"password",autocomplete:"new-password",required:"",maxlength:"200"}),c=el("input",{id:"confirm-password",type:"password",autocomplete:"new-password",required:"",maxlength:"200"});f.append(el("label",{for:"new-password"},"New password"),a,el("label",{for:"confirm-password"},"Type it again"),c,el("div",{class:"actions"},el("button",{type:"submit"},"Save new password")));f.addEventListener("submit",async e=>{e.preventDefault();if(a.value!==c.value){setMessage("The two passwords do not match. Please type them again.");render();return;}const d=await api("/api/recovery/password",{token:sessionStorage.getItem(tokenKey)||"",password:a.value});if(invalidRecovery(d))return;if(!d.ok){setMessage(d.message);render();return;}sessionStorage.removeItem(tokenKey);serverStage="resetComplete";current="success";setMessage("Your password has been changed securely.");render();});b.append(f);return tail(b);}
function successView(){const b=card("Password changed");b.append(el("div",{class:"notice"},"Your new password is ready to use."),el("div",{class:"next"},el("strong",{},"Next step: "),"sign in, then complete one-time verification."),el("div",{class:"actions"},button("Go to sign in",()=>{current="login";save();render();})));return tail(b);}
function loginView(){const b=card("Sign in");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"enter your account email and your new password."));showMessage(b);const f=el("form",{}),e=el("input",{id:"login-email",type:"email",autocomplete:"username",required:"",maxlength:"160"}),pword=el("input",{id:"login-password",type:"password",autocomplete:"current-password",required:"",maxlength:"200"});f.append(el("label",{for:"login-email"},"Account email"),e,el("label",{for:"login-password"},"Password"),pword,el("div",{class:"actions"},el("button",{type:"submit"},"Sign in"),button("Reset password instead",()=>{current="start";save();render();},true)));f.addEventListener("submit",async x=>{x.preventDefault();const d=await api("/api/login",{email:e.value,password:pword.value});if(!d.ok){setMessage(d.message);render();return;}addLog("SIMULATED MFA DELIVERY: one-time verification code: "+d.mfaCode);serverStage="mfa";current="mfa";setMessage("Password accepted. Your one-time code is in the Logs panel.");render();});b.append(f);return tail(b);}
function mfaView(){const b=card("One more safety check");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"enter the one-time verification code from the Logs panel."));showMessage(b);const f=el("form",{}),i=el("input",{id:"mfa",type:"text",autocomplete:"one-time-code",required:"",maxlength:"6"});f.append(el("label",{for:"mfa"},"One-time code"),i,p("This demo code stays valid while this active sign-in step is open. There is no rush.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Verify and continue")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/mfa",{code:i.value.trim()});if(!d.ok){setMessage(d.message);render();return;}serverStage="authenticated";current="privacy";setMessage("You are signed in. Review the privacy statement below.");render();});b.append(f);return tail(b);}
function privacyView(){const b=card("Privacy statement");b.append(el("div",{class:"notice"},"Authenticated account session active."),p("Hospital authorities need your explicit acceptance of the updated privacy conditions before appointment support can continue."),el("div",{class:"next"},el("strong",{},"Next step: "),"read this short statement and select Accept privacy statement when ready."),el("h2",{},"Updated privacy conditions"),p("Your account information is used to support your healthcare appointment and medication review. Access is limited to authorised hospital care processes."));showMessage(b);b.append(el("div",{class:"actions"},button("Accept privacy statement",async()=>{const d=await api("/api/privacy/accept",{});if(!d.ok){setMessage(d.message);render();return;}current="confirmed";setMessage("Privacy statement accepted. Appointment support may now continue.");render();})));return tail(b);}
function confirmedView(){const b=card("Privacy statement accepted");b.append(el("div",{class:"notice"},"Confirmation recorded in this simulated authenticated session."),p("Hospital authorities can now continue with appointment support for your medication dosage review."),p("You can safely close this page when you are ready.","quiet"));return tail(b);}
function helpView(){const b=card("Help and safety advice");b.append(p("You can pause at any point. The portal restores only a step that still matches your active secure server session."),el("h2",{},"Keep your account safe"),el("ul",{},el("li",{},"Only sign in on this Care Portal address."),el("li",{},"Never share your password or recovery code by email, phone call, or message."),el("li",{},"Hospital staff will not ask you to read out a password."),el("li",{},"If something feels unexpected, stop and contact your usual hospital support channel.")));b.append(el("div",{class:"actions"},button("Return to my step",()=>{const s=(()=>{try{return JSON.parse(localStorage.getItem(storageKey)||"{}");}catch{return {};}})();current=s.serverStage===serverStage?s.current:"start";if(current==="help")current="start";render();},true)));return b;}
function render(){renderProgress();clear(app);const view=({start:startView,channel:channelView,delivery:deliveryView,verify:verifyView,password:passwordView,success:successView,login:loginView,mfa:mfaView,privacy:privacyView,confirmed:confirmedView,help:helpView})[current]||startView;app.append(view(),logPanel());document.getElementById("main").focus();}
document.getElementById("footer-help").addEventListener("click",e=>{e.preventDefault();current="help";render();});
window.addEventListener("hashchange",()=>{if(location.hash==="#help"){current="help";render();}});
bootstrap();
})();
</script>
</body>
</html>`;
}

async function handleApi(request: Request, path: string) {
  if (path === "/api/bootstrap" && request.method === "GET") {
    let session = getSession(request);
    let cookie: string | undefined;
    if (!session) {
      session = createSession();
      cookie = sessionCookie(session);
    }
    return json({ ok: true, csrf: session.csrf }, 200, cookie);
  }

  if (path === "/api/status" && request.method === "GET") {
    const session = getSession(request);
    if (!session) return json({ ok: true, stage: "anonymous", recoveryExpired: false });
    const recoveryExpired = expireRecoveryIfNeeded(session);
    // Server-backed state intentionally exposes no account identifier or recovery secret.
    return json({ ok: true, stage: session.stage, recoveryExpired, privacyAccepted: !!session.privacyAccepted });
  }

  // [1] Every state-changing request is same-origin and protected by a unique session CSRF token.
  if (request.method !== "POST") return genericError(405);
  const session = csrfSession(request);
  if (!session) return genericError(403);

  let data: Record<string, unknown>;
  try {
    data = await requestData(request);
  } catch {
    return genericError();
  }

  if (path === "/api/recovery/start") {
    if (!isAllowedEmail(data.email) || !["anonymous", "channel"].includes(session.stage)) return genericError();
    session.stage = "channel";
    session.userId = typeof data.email === "string" && data.email.toLowerCase() === INTERNAL_ACCOUNT.login
      ? INTERNAL_ACCOUNT.id
      : undefined;
    session.channelHash = digest(APPROVED_CHANNEL_CODE);
    session.resetHash = undefined;
    session.resetExpires = undefined;
    session.resetUsed = false;
    console.log("SIMULATED SERVER: approved recovery-channel confirmation requested.");
    return json({
      ok: true,
      message: "If this account can be recovered, confirm the approved recovery channel next.",
    });
  }

  // [4] Reset material cannot be issued until a separate approved-channel verification succeeds.
  if (path === "/api/recovery/channel") {
    if (session.stage !== "channel" || typeof data.code !== "string" ||
      !/^\d{6}$/.test(data.code) || !session.channelHash ||
      !safeEqual(digest(data.code), session.channelHash) || !session.userId) {
      return genericError();
    }
    const resetToken = randomToken();
    session.stage = "recovery";
    session.channelHash = undefined;
    session.resetHash = digest(resetToken);
    session.resetExpires = Date.now() + RESET_TTL;
    session.resetUsed = false;
    console.log("SIMULATED SERVER: approved channel verified; private reset delivery created.");
    return json({ ok: true, token: resetToken });
  }

  if (path === "/api/recovery/verify") {
    if (expireRecoveryIfNeeded(session)) return recoveryStateError(session);
    if (session.stage !== "recovery" || !isToken(data.token) || !session.resetHash ||
      session.resetUsed || !safeEqual(digest(data.token as string), session.resetHash) || !session.userId) {
      return recoveryStateError(session);
    }
    session.stage = "verified";
    return json({ ok: true });
  }

  if (path === "/api/recovery/password") {
    const problem = passwordProblem(data.password);
    if (problem) return json({ ok: false, message: problem });
    if (expireRecoveryIfNeeded(session)) return recoveryStateError(session);
    if (session.stage !== "verified" || !session.userId || !isToken(data.token) ||
      !session.resetHash || session.resetUsed ||
      !safeEqual(digest(data.token as string), session.resetHash)) {
      return recoveryStateError(session);
    }
    // [4] Argon2id hashes password data. Plaintext is neither stored nor logged.
    INTERNAL_ACCOUNT.passwordHash = await Bun.password.hash(data.password as string, { algorithm: "argon2id" });
    session.resetUsed = true;
    session.resetHash = undefined;
    session.resetExpires = undefined;
    session.stage = "resetComplete";
    console.log("SIMULATED SERVER: password updated; reset token invalidated.");
    return json({ ok: true });
  }

  if (path === "/api/login") {
    if (!isAllowedEmail(data.email) || typeof data.password !== "string" || data.password.length > 200) {
      return genericError();
    }
    const key = digest((data.email as string).toLowerCase());
    const attempts = loginFailures.get(key) || { failures: 0, lockedUntil: 0 };
    if (attempts.lockedUntil > Date.now()) return genericError(429);

    const matchesEmail = (data.email as string).toLowerCase() === INTERNAL_ACCOUNT.login;
    let matchesPassword = false;
    try {
      matchesPassword = matchesEmail && await Bun.password.verify(data.password as string, INTERNAL_ACCOUNT.passwordHash);
    } catch {
      matchesPassword = false;
    }
    if (!matchesPassword) {
      attempts.failures++;
      if (attempts.failures >= 5) {
        attempts.failures = 0;
        attempts.lockedUntil = Date.now() + 10 * 60 * 1000;
      }
      loginFailures.set(key, attempts);
      return genericError();
    }

    loginFailures.delete(key);
    session.stage = "mfa";
    session.userId = INTERNAL_ACCOUNT.id;
    session.mfaAttempts = 0;
    session.mfaCode = MFA_CODE;
    console.log("SIMULATED SERVER: password accepted; MFA challenge created.");
    return json({ ok: true, mfaCode: MFA_CODE });
  }

  if (path === "/api/mfa") {
    if (session.stage !== "mfa" || typeof data.code !== "string" || !/^\d{6}$/.test(data.code)) {
      return genericError();
    }
    session.mfaAttempts++;
    if (session.mfaAttempts > 5 || !session.mfaCode || !safeEqual(data.code, session.mfaCode)) {
      return genericError();
    }
    session.stage = "authenticated";
    session.mfaCode = undefined;
    session.privacyAccepted = false;
    console.log("SIMULATED SERVER: MFA verified; authenticated session active.");
    return json({ ok: true });
  }

  if (path === "/api/privacy/accept") {
    if (session.stage !== "authenticated" || !session.userId) return genericError(403);
    session.privacyAccepted = true;
    console.log("SIMULATED SERVER: authenticated privacy statement acceptance recorded.");
    return json({ ok: true });
  }

  if (path === "/api/logout") {
    if (session.stage !== "authenticated") return genericError(403);
    sessions.delete(session.id);
    return json({ ok: true }, 200, "recovery_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  }

  return genericError(404);
}

async function handler(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);

    // [5] Only fixed local SPA paths exist; no redirects or user-controlled destinations are used.
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery/verify")) {
      const nonce = randomToken(18);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch {
    return new Response("Service unavailable", { status: 503, headers: baseHeaders() });
  }
}

const certPath = Bun.file("certs/cert.pem");
const keyPath = Bun.file("certs/key.pem");
if (!(await certPath.exists()) || !(await keyPath.exists())) {
  console.error("HTTPS certificates are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

// [3] HTTPS-only listener, HSTS, CSP, Secure cookies, and no diagnostic responses.
Bun.serve({
  port: PORT,
  hostname: "localhost",
  tls: { cert: await certPath.text(), key: await keyPath.text() },
  fetch: handler,
});

console.log(`Care Portal securely listening at https://localhost:${PORT}`);
