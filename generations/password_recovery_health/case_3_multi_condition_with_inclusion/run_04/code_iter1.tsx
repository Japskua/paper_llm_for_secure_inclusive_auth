
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System — single Bun HTTPS server + inline SPA.
  Security comments map to requirements:
  [1] access control/CSRF, [2] XSS, [3] HTTPS/security headers,
  [4] authentication/password/MFA, [5] safe-authentication guidance.
  Inclusivity comments map to calm, persistent, step-by-step interaction.
*/

type Stage = "anonymous" | "recovery" | "verified" | "mfa" | "authenticated";
type Session = {
  id: string;
  csrf: string;
  stage: Stage;
  createdAt: number;
  userId?: string;
  resetHash?: string;
  resetExpires?: number;
  resetUsed?: boolean;
  resetVerified?: boolean;
  mfaCode?: string;
  mfaAttempts: number;
};

const sessions = new Map<string, Session>();
const loginFailures = new Map<string, { failures: number; lockedUntil: number }>();

// [4] This opaque internal ID is never sent to the browser or included in messages.
const INTERNAL_ACCOUNT = {
  id: "account-1",
  login: "helena.patient@hospital.test",
  passwordHash: await Bun.password.hash("Hospital!Safe2025", { algorithm: "argon2id" }),
};

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_TTL = 24 * 60 * 60 * 1000;
const RESET_TTL = 15 * 60 * 1000;
const MFA_CODE = "246810"; // deterministic mock code, valid for this active MFA flow only

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
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
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
    if (id) sessions.delete(id);
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
  // [1][3][4] HttpOnly + Secure + Strict cookie protects the session from scripts/cross-site use.
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
    "Pragma": "no-cache",
  });
  if (nonce) {
    // [2] Nonce-only inline script/style policy; no external sources, objects, frames, or base URL.
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
  // [1][3][4] Never disclose account, token, session, or diagnostic details.
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}

function validSameOrigin(request: Request) {
  // [1] Browser POSTs must be from this exact HTTPS origin. Missing Origin is rejected.
  const origin = request.headers.get("origin");
  try {
    return !!origin && origin === new URL(request.url).origin;
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
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) throw new Error("oversized");
  return await request.json() as Record<string, unknown>;
}

/* [2] The client uses only DOM constructors and textContent for all dynamic UI. */
function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Care Portal – Password recovery</title>
<style nonce="${nonce}">
:root{--ink:#193447;--muted:#5d6f7c;--blue:#075a8c;--blue2:#e9f5fb;--line:#c8d8e1;--good:#155d3a;--warn:#6f4c00;--paper:#fff;--bg:#f4f8fa}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.52 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:#064f7b;font-weight:650} button,input{font:inherit} button{cursor:pointer;border-radius:8px;border:0;padding:.7rem 1.05rem;font-weight:750;background:var(--blue);color:white}button:hover{background:#03466d}button.secondary{background:white;color:var(--blue);border:2px solid var(--blue)}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #e49a21;outline-offset:3px}
.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:.5rem;z-index:3}.top{border-bottom:1px solid var(--line);background:white}.topin,main,footer{max-width:820px;margin:auto;padding-left:1.2rem;padding-right:1.2rem}.topin{padding-top:1rem;padding-bottom:1rem}.brand{font-size:1.25rem;font-weight:800}.tag{color:var(--muted);font-size:.94rem}
.progress{padding:1rem 0;border-top:1px solid #e4edf1}.progress ol{list-style:none;display:flex;gap:.4rem;margin:0;padding:0;flex-wrap:wrap}.progress li{font-size:.88rem;border-radius:20px;padding:.25rem .65rem;background:#edf2f5;color:var(--muted)}.progress li.now{background:#ccecf9;color:#063e60;font-weight:800}.progress li.done{background:#d9f1df;color:var(--good)}
main{padding-top:2rem;padding-bottom:1.2rem;min-height:61vh}.card{max-width:650px;background:var(--paper);padding:1.45rem;border:1px solid var(--line);border-radius:13px;box-shadow:0 2px 8px #1231 11}h1{font-size:1.7rem;line-height:1.25;margin:.1rem 0 .7rem}h2{font-size:1.15rem;margin:1.2rem 0 .4rem}p{margin:.55rem 0}.next{background:var(--blue2);border-left:5px solid var(--blue);padding:.8rem 1rem;margin:1rem 0}.notice{padding:.8rem 1rem;border-radius:8px;margin:1rem 0;background:#edf7ef;color:var(--good)}.warning{background:#fff7e4;color:var(--warn)}label{display:block;font-weight:750;margin-top:1rem}input{display:block;width:100%;padding:.65rem;border:2px solid #78909f;border-radius:7px;margin-top:.3rem}.hint{font-size:.9rem;color:var(--muted)}.actions{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:1.2rem}.quiet{font-size:.92rem;color:var(--muted)}.helpbox{margin-top:1.1rem;border-top:1px solid var(--line);padding-top:1rem}.logpanel{margin-top:1rem;background:#10232d;color:#d8edf5;border-radius:10px;padding:.8rem}.logpanel h2{margin:0 0 .4rem;font-size:1rem}.logs{white-space:pre-wrap;word-break:break-word;font:13px/1.4 ui-monospace,SFMono-Regular,monospace;max-height:150px;overflow:auto}.hidden{display:none}footer{padding-bottom:2rem;color:var(--muted);font-size:.88rem}@media(max-width:500px){body{font-size:17px}.card{padding:1rem}.progress ol{display:grid;grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to the current step</a>
<header class="top"><div class="topin"><div class="brand">Care Portal</div><div class="tag">Private account recovery</div><nav class="progress" aria-label="Recovery progress"><ol id="progress"></ol></nav></div></header>
<main id="main" tabindex="-1"><div id="app" aria-live="polite">Preparing your private recovery space…</div></main>
<footer>Take your time. This recovery does not have a countdown on this page. <a href="#help" id="footer-help">Get help and safety advice</a></footer>
<script nonce="${nonce}">
(() => {
"use strict";
/* Inclusivity: persistent simple steps, no automatic expiry display, visible next action and help. */
const app=document.getElementById("app"), progress=document.getElementById("progress");
const STEP_NAMES=["1. Start","2. Check code","3. New password","4. Sign in"];
let csrf="", current="start", message="";
const stored=JSON.parse(localStorage.getItem("care-recovery-progress")||"{}");
const tokenKey="care-recovery-token";
function save(){localStorage.setItem("care-recovery-progress",JSON.stringify({current,message}));}
function clearNode(node){while(node.firstChild)node.removeChild(node.firstChild);}
function el(tag, props={}, ...children){const node=document.createElement(tag);for(const [key,value] of Object.entries(props)){if(key==="class")node.className=value;else if(key==="type")node.type=value;else if(key==="href")node.href=value;else if(key==="id")node.id=value;else if(key==="value")node.value=value;else if(key==="placeholder")node.placeholder=value;else if(key==="autocomplete")node.autocomplete=value;else if(key.startsWith("aria-"))node.setAttribute(key,String(value));else if(key==="onclick")node.addEventListener("click",value);else node.setAttribute(key,String(value));}for(const child of children.flat()){if(child===null||child===undefined)continue;node.append(child.nodeType?child:document.createTextNode(String(child)));}return node;}
function paragraph(text, cls=""){return el("p",cls?{class:cls}:{},text);}
function card(title){return el("section",{class:"card","aria-labelledby":"page-title"},el("h1",{id:"page-title"},title));}
function setMessage(text){message=text;save();}
function renderProgress(){clearNode(progress);const index={start:0,delivery:1,verify:1,password:2,success:3,login:3,mfa:3,help:0}[current]??0;STEP_NAMES.forEach((name,i)=>progress.append(el("li",{class:i===index?"now":i<index?"done":""},name)));}
function helpLink(){const a=el("a",{href:"#help"},"Help and safety advice");a.addEventListener("click",e=>{e.preventDefault();current="help";save();render();});return a;}
function standardTail(box){box.append(el("div",{class:"helpbox"},paragraph("Need a pause? Your step is saved in this browser. You can return here when ready.","quiet"),paragraph("", "quiet").append?document.createTextNode(""):""));const p=el("p",{class:"quiet"},"Need support? ");p.append(helpLink());box.append(p);return box;}
function notice(box){if(message)box.append(el("div",{class:"notice"},message));}
function logsPanel(){const wrap=el("aside",{class:"logpanel","aria-label":"Simulation logs"},el("h2",{},"Logs"),el("div",{class:"logs",id:"logs"},"No simulated messages yet."));return wrap;}
function log(text){console.log(text);const panel=document.getElementById("logs");if(panel){if(panel.textContent==="No simulated messages yet.")panel.textContent="";panel.textContent+=(panel.textContent?"\\n":"")+text;}}
async function api(path, body){const response=await fetch(path,{method:body===undefined?"GET":"POST",credentials:"same-origin",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)});let data={ok:false,message:"We could not complete that step."};try{data=await response.json();}catch{}return data;}
async function bootstrap(){const data=await api("/api/bootstrap");if(!data.ok){setMessage("Your private recovery space could not be prepared. Refresh and try again.");render();return;}csrf=data.csrf;if(stored.current&&["delivery","verify","password","login","mfa"].includes(stored.current))current=stored.current;const routeToken=new URLSearchParams(location.search).get("token");if(location.pathname==="/recovery/verify"&&routeToken&&/^[A-Za-z0-9_-]{40,100}$/.test(routeToken)){sessionStorage.setItem(tokenKey,routeToken);current="verify";setMessage("Recovery link opened. Check the code below to continue.");}render();}
function startView(){const box=card("Reset your password");box.append(paragraph("We will guide you one small step at a time."));box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("enter the email address you use for your account.")));notice(box);const form=el("form",{});const email=el("input",{id:"email",type:"email",autocomplete:"email",required:"",maxlength:"160"});form.append(el("label",{for:"email"},"Account email"),email,paragraph("For privacy, we give the same message whether or not an account can be recovered.","hint"));form.append(el("div",{class:"actions"},el("button",{type:"submit"},"Continue")));form.addEventListener("submit",async e=>{e.preventDefault();const data=await api("/api/recovery/start",{email:email.value});if(!data.ok){setMessage(data.message);render();return;}if(data.token){sessionStorage.setItem(tokenKey,data.token);log("SIMULATED RECOVERY DELIVERY: private reset code: "+data.token);log("SIMULATED RECOVERY DELIVERY: verification link: "+location.origin+"/recovery/verify?token="+data.token);}setMessage(data.message);current="delivery";save();render();});box.append(form);return standardTail(box);}
function deliveryView(){const box=card("Check your recovery message");box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("open the simulated recovery link, or enter the code yourself.")));notice(box);box.append(paragraph("For this safe demo, the private delivery code is shown only in the browser console and the Logs panel after it is issued. In a real service it would arrive through your approved recovery channel."));const token=sessionStorage.getItem(tokenKey);if(token&&/^[A-Za-z0-9_-]{40,100}$/.test(token)){const a=el("a",{href:"/recovery/verify?token="+encodeURIComponent(token)},"Open simulated recovery link");box.append(el("div",{class:"actions"},a));}else box.append(paragraph("If you no longer have your code, start again to request a fresh one.","quiet"));const btn=el("button",{class:"secondary",type:"button",onclick:()=>{current="verify";save();render();}},"Enter a code manually");box.append(el("div",{class:"actions"},btn));return standardTail(box);}
function verifyView(){const box=card("Check your recovery code");box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("paste or type the private code, then select Check code.")));notice(box);const form=el("form",{});const input=el("input",{id:"code",type:"text",autocomplete:"one-time-code",required:"",maxlength:"100",placeholder:"Recovery code"});const saved=sessionStorage.getItem(tokenKey);if(saved&&/^[A-Za-z0-9_-]{40,100}$/.test(saved))input.value=saved;form.append(el("label",{for:"code"},"Recovery code"),input,paragraph("Codes are private. Never share a password or code with anyone who contacts you unexpectedly.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Check code")));form.addEventListener("submit",async e=>{e.preventDefault();const code=input.value.trim();const data=await api("/api/recovery/verify",{token:code});if(!data.ok){setMessage(data.message);render();return;}sessionStorage.setItem(tokenKey,code);setMessage("Code checked. You can now choose a new password.");current="password";save();history.replaceState({}, "", "/");render();});box.append(form);return standardTail(box);}
function passwordView(){const box=card("Choose a new password");box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("create your new password, then save it.")));notice(box);box.append(el("h2",{},"Password checklist"));box.append(el("ul",{},el("li",{},"At least 12 characters"),el("li",{},"An uppercase and lowercase letter"),el("li",{},"A number and a symbol"),el("li",{},"No spaces")));const form=el("form",{});const pass=el("input",{id:"new-password",type:"password",autocomplete:"new-password",required:"",maxlength:"200"});const confirm=el("input",{id:"confirm-password",type:"password",autocomplete:"new-password",required:"",maxlength:"200"});form.append(el("label",{for:"new-password"},"New password"),pass,el("label",{for:"confirm-password"},"Type it again"),confirm,el("div",{class:"actions"},el("button",{type:"submit"},"Save new password")));form.addEventListener("submit",async e=>{e.preventDefault();if(pass.value!==confirm.value){setMessage("The two passwords do not match. Please type them again.");render();return;}const token=sessionStorage.getItem(tokenKey)||"";const data=await api("/api/recovery/password",{token,password:pass.value});if(!data.ok){setMessage(data.message);render();return;}sessionStorage.removeItem(tokenKey);setMessage("Your password has been changed securely.");current="success";save();render();});box.append(form);return standardTail(box);}
function successView(){const box=card("Password changed");box.append(el("div",{class:"notice"},"Your new password is ready to use."));box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("sign in, then complete the one-time verification step.")));const b=el("button",{type:"button",onclick:()=>{current="login";save();render();}},"Go to sign in");box.append(el("div",{class:"actions"},b));return standardTail(box);}
function loginView(){const box=card("Sign in");box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("enter your account email and your new password.")));notice(box);const form=el("form",{}),email=el("input",{id:"login-email",type:"email",autocomplete:"username",required:"",maxlength:"160"}),pass=el("input",{id:"login-password",type:"password",autocomplete:"current-password",required:"",maxlength:"200"});form.append(el("label",{for:"login-email"},"Account email"),email,el("label",{for:"login-password"},"Password"),pass,el("div",{class:"actions"},el("button",{type:"submit"},"Sign in"),el("button",{class:"secondary",type:"button",onclick:()=>{current="start";save();render();}},"Reset password instead")));form.addEventListener("submit",async e=>{e.preventDefault();const data=await api("/api/login",{email:email.value,password:pass.value});if(!data.ok){setMessage(data.message);render();return;}log("SIMULATED MFA DELIVERY: one-time verification code: "+data.mfaCode);setMessage("Password accepted. Your one-time code is in the simulated delivery Logs panel.");current="mfa";save();render();});box.append(form);return standardTail(box);}
function mfaView(){const box=card("One more safety check");box.append(el("div",{class:"next"},el("strong",{},"Next step: "),document.createTextNode("enter the one-time verification code from the Logs panel.")));notice(box);const form=el("form",{}),input=el("input",{id:"mfa",type:"text",autocomplete:"one-time-code",required:"",maxlength:"6"});form.append(el("label",{for:"mfa"},"One-time code"),input,paragraph("This demo code stays valid while this active sign-in step is open. There is no rush.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Verify and continue")));form.addEventListener("submit",async e=>{e.preventDefault();const data=await api("/api/mfa",{code:input.value.trim()});if(!data.ok){setMessage(data.message);render();return;}setMessage("You are signed in. You may now review the privacy statement and continue with appointment support.");current="success";save();render();});box.append(form);return standardTail(box);}
function helpView(){const box=card("Help and safety advice");box.append(paragraph("You can pause at any point. This browser remembers your current step, and there is no page countdown."));box.append(el("h2",{},"Keep your account safe"),el("ul",{},el("li",{},"Only sign in on this Care Portal address."),el("li",{},"Never share your password or recovery code by email, phone call, or message."),el("li",{},"Hospital staff will not ask you to read out a password."),el("li",{},"If something feels unexpected, stop and contact your usual hospital support channel.")));const back=el("button",{class:"secondary",type:"button",onclick:()=>{current=stored.current||"start";if(current==="help")current="start";save();render();}},"Return to my step");box.append(el("div",{class:"actions"},back));return box;}
function render(){renderProgress();clearNode(app);let view=current==="start"?startView():current==="delivery"?deliveryView():current==="verify"?verifyView():current==="password"?passwordView():current==="success"?successView():current==="login"?loginView():current==="mfa"?mfaView():helpView();app.append(view,logsPanel());document.getElementById("main").focus();}
document.getElementById("footer-help").addEventListener("click",e=>{e.preventDefault();current="help";save();render();});
window.addEventListener("hashchange",()=>{if(location.hash==="#help"){current="help";save();render();}});
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

  // [1] Every state-changing endpoint below is POST, exact same-origin, and per-session CSRF protected.
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
    if (!isAllowedEmail(data.email) || !["anonymous", "recovery"].includes(session.stage)) return genericError();

    // Privacy-preserving response is identical. In this deterministic mock, recovery is tied to
    // the existing opaque account only after the supplied login matches server-side.
    session.stage = "recovery";
    session.userId = typeof data.email === "string" && data.email.toLowerCase() === INTERNAL_ACCOUNT.login
      ? INTERNAL_ACCOUNT.id
      : undefined;
    const resetToken = randomToken();
    session.resetHash = digest(resetToken);
    session.resetExpires = Date.now() + RESET_TTL;
    session.resetUsed = false;
    session.resetVerified = false;

    console.log("SIMULATED SERVER: recovery delivery created for a private account flow.");
    // Mock-only token delivery is returned to the same authenticated Secure/HttpOnly session response.
    return json({
      ok: true,
      message: "If this account can be recovered, a private recovery message has been prepared.",
      token: resetToken,
    });
  }

  if (path === "/api/recovery/verify") {
    if (session.stage !== "recovery" || !isToken(data.token) || !session.resetHash ||
      !session.resetExpires || session.resetUsed || Date.now() > session.resetExpires ||
      !safeEqual(digest(data.token as string), session.resetHash) || !session.userId) {
      return genericError();
    }
    session.resetVerified = true;
    session.stage = "verified";
    return json({ ok: true });
  }

  if (path === "/api/recovery/password") {
    const problem = passwordProblem(data.password);
    if (problem) return json({ ok: false, message: problem });
    if (session.stage !== "verified" || !session.userId || !isToken(data.token) ||
      !session.resetHash || !session.resetExpires || session.resetUsed ||
      Date.now() > session.resetExpires || !safeEqual(digest(data.token as string), session.resetHash)) {
      return genericError();
    }

    // [4] Bun Argon2id hashes the password; plaintext is never stored or logged.
    INTERNAL_ACCOUNT.passwordHash = await Bun.password.hash(data.password as string, { algorithm: "argon2id" });
    session.resetUsed = true; // [3][4] random reset token becomes single-use after successful update.
    session.resetHash = undefined;
    session.resetExpires = undefined;
    session.stage = "anonymous";
    console.log("SIMULATED SERVER: password updated; reset token invalidated.");
    return json({ ok: true });
  }

  if (path === "/api/login") {
    if (!isAllowedEmail(data.email) || typeof data.password !== "string" || data.password.length > 200) return genericError();
    const key = digest((data.email as string).toLowerCase());
    const attempts = loginFailures.get(key) || { failures: 0, lockedUntil: 0 };
    if (attempts.lockedUntil > Date.now()) return genericError(429);

    const matchesEmail = (data.email as string).toLowerCase() === INTERNAL_ACCOUNT.login;
    const matchesPassword = matchesEmail && await Bun.password.verify(data.password, INTERNAL_ACCOUNT.passwordHash);
    if (!matchesPassword) {
      attempts.failures++;
      if (attempts.failures >= 5) {
        attempts.failures = 0;
        attempts.lockedUntil = Date.now() + 10 * 60 * 1000;
      }
      loginFailures.set(key, attempts);
      // [4] Generic result prevents account/password enumeration.
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
    if (session.stage !== "mfa" || typeof data.code !== "string" || !/^\d{6}$/.test(data.code)) return genericError();
    session.mfaAttempts++;
    if (session.mfaAttempts > 5 || !session.mfaCode || !safeEqual(data.code, session.mfaCode)) return genericError();
    session.stage = "authenticated";
    session.mfaCode = undefined;
    console.log("SIMULATED SERVER: MFA verified; authenticated session active.");
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

    // [5] Only fixed SPA routes are served. Token query values are handled client-side with a fixed format.
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery/verify")) {
      const nonce = randomToken(18);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }

    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch {
    // [3] Suppress stack traces and implementation details.
    return new Response("Service unavailable", { status: 503, headers: baseHeaders() });
  }
}

const certPath = Bun.file("certs/cert.pem");
const keyPath = Bun.file("certs/key.pem");

if (!(await certPath.exists()) || !(await keyPath.exists())) {
  console.error("HTTPS certificates are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

// [3] HTTPS-only Bun listener; Secure cookies and HSTS are used throughout.
Bun.serve({
  port: PORT,
  hostname: "localhost",
  tls: {
    cert: await certPath.text(),
    key: await keyPath.text(),
  },
  fetch: handler,
});

console.log(`Care Portal securely listening at https://localhost:${PORT}`);
