
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

/*
 Password Recovery System — Bun HTTPS server and inline vanilla-JS SPA.
 [1] Access control / CSRF   [2] XSS prevention   [3] secure configuration
 [4] Authentication / MFA    [5] anti-phishing guidance
*/

type Stage =
  | "anonymous" | "channel" | "recovery" | "verified" | "resetComplete"
  | "mfa" | "mfaExhausted" | "authenticated";

type Session = {
  id: string; csrf: string; stage: Stage; createdAt: number;
  userId?: string; channelHash?: string; resetHash?: string;
  resetExpires?: number; resetUsed?: boolean;
  channelAttempts: number; channelLockedUntil: number;
  resetVerifyAttempts: number; resetVerifyLockedUntil: number;
  mfaCode?: string; mfaAttempts: number; privacyAccepted?: boolean;
};

const sessions = new Map<string, Session>();
const loginFailures = new Map<string, { failures: number; lockedUntil: number }>();

const INTERNAL_ACCOUNT = {
  id: "account-1",
  login: "helena.patient@hospital.test",
  passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRmb3Jtb2NrMTI$VYqXJcKzPzx2CJCPHcGXN6YPgOxWrG1HQzNl0lhy8SQ",
};

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_TTL = 24 * 60 * 60 * 1000;
const RESET_TTL = 15 * 60 * 1000;
const LOCK_TTL = 10 * 60 * 1000;
const MAX_RECOVERY_ATTEMPTS = 5;
const MFA_CODE = "246810";
const RECOVERY_RESPONSE_DELAY = 125;

function randomToken(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function digest(value: string) { return createHash("sha256").update(value).digest("hex"); }
function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function pause(ms: number) { return new Promise(resolve => setTimeout(resolve, ms)); }
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) result[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return result;
}
function getSession(request: Request) {
  const id = parseCookies(request).recovery_session;
  if (!id || !/^[A-Za-z0-9_-]{30,90}$/.test(id)) return undefined;
  const session = sessions.get(id);
  if (!session || Date.now() - session.createdAt > SESSION_TTL) {
    sessions.delete(id || "");
    return undefined;
  }
  return session;
}
function createSession(): Session {
  const session: Session = {
    id: randomToken(), csrf: randomToken(), stage: "anonymous", createdAt: Date.now(),
    channelAttempts: 0, channelLockedUntil: 0,
    resetVerifyAttempts: 0, resetVerifyLockedUntil: 0, mfaAttempts: 0,
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(session: Session) {
  return `recovery_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}
function baseHeaders(nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, private, max-age=0", Pragma: "no-cache",
  });
  if (nonce) h.set("Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
  return h;
}
function json(body: Record<string, unknown>, status = 200, cookie?: string) {
  const h = baseHeaders();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) h.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers: h });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}
function validSameOrigin(request: Request) {
  try { return !!request.headers.get("origin") && request.headers.get("origin") === new URL(request.url).origin; }
  catch { return false; }
}
function csrfSession(request: Request) {
  const s = getSession(request), token = request.headers.get("x-csrf-token") || "";
  return s && validSameOrigin(request) && safeEqual(s.csrf, token) ? s : undefined;
}
function isAllowedEmail(v: unknown) {
  return typeof v === "string" && v.length <= 160 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_\`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(v);
}
function isToken(v: unknown) { return typeof v === "string" && /^[A-Za-z0-9_-]{40,100}$/.test(v); }
function passwordProblem(p: unknown) {
  if (typeof p !== "string") return "Enter a new password.";
  if (p.length < 12) return "Use at least 12 characters.";
  if (p.length > 200) return "Please use 200 characters or fewer.";
  if (!/[a-z]/.test(p)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(p)) return "Include an uppercase letter.";
  if (!/\d/.test(p)) return "Include a number.";
  if (!/[^A-Za-z0-9\s]/.test(p)) return "Include a symbol.";
  if (/\s/.test(p)) return "Do not use spaces.";
  return "";
}
async function requestData(request: Request) {
  if (Number(request.headers.get("content-length") || "0") > 10000) throw new Error("oversized");
  return await request.json() as Record<string, unknown>;
}
function clearRecovery(session: Session) {
  session.stage = "anonymous";
  session.userId = undefined;
  session.channelHash = undefined;
  session.resetHash = undefined;
  session.resetExpires = undefined;
  session.resetUsed = true;
  session.channelAttempts = 0;
  session.channelLockedUntil = 0;
  session.resetVerifyAttempts = 0;
  session.resetVerifyLockedUntil = 0;
  session.mfaCode = undefined;
  session.mfaAttempts = 0;
  session.privacyAccepted = undefined;
}
function expireRecoveryIfNeeded(session: Session) {
  if ((session.stage === "recovery" || session.stage === "verified") &&
    (!session.resetExpires || Date.now() > session.resetExpires || session.resetUsed)) {
    clearRecovery(session);
    return true;
  }
  return false;
}
function recoveryStateError(session: Session) {
  expireRecoveryIfNeeded(session);
  return json({ ok: false, invalidRecovery: true, message: "This recovery step is no longer available. Start recovery again when you are ready." });
}
function lockedRecoveryError() {
  return json({ ok: false, locked: true, message: "Too many attempts were made. Please pause and try this step again later." }, 429);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Care Portal – Password recovery</title>
<style nonce="${nonce}">
:root{--ink:#193447;--muted:#5d6f7c;--blue:#075a8c;--pale:#e9f5fb;--line:#c8d8e1;--good:#155d3a;--paper:#fff;--bg:#f4f8fa}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.5 system-ui,sans-serif}button,input{font:inherit}button{cursor:pointer;border:0;border-radius:8px;padding:.7rem 1rem;background:var(--blue);color:#fff;font-weight:750}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #e49a21;outline-offset:3px}a{color:#075a8c;font-weight:700}.top{background:#fff;border-bottom:1px solid var(--line)}.topin,main,footer{max-width:820px;margin:auto;padding-left:1.2rem;padding-right:1.2rem}.topin{padding-top:1rem;padding-bottom:1rem}.brand{font-weight:800;font-size:1.25rem}.tag,.quiet,.hint,footer{color:var(--muted);font-size:.92rem}.progress ol{display:flex;list-style:none;gap:.4rem;padding:0;flex-wrap:wrap}.progress li{padding:.2rem .6rem;border-radius:16px;background:#edf2f5;font-size:.85rem}.progress .now{background:#ccecf9;font-weight:800}.progress .done{background:#d9f1df;color:var(--good)}main{min-height:64vh;padding-top:2rem}.card{max-width:650px;background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:1.4rem}h1{font-size:1.7rem;line-height:1.2;margin:.1rem 0 .7rem}h2{font-size:1.15rem}.next,.notice{margin:1rem 0;padding:.8rem 1rem;border-radius:7px}.next{background:var(--pale);border-left:5px solid var(--blue)}.notice{background:#edf7ef;color:var(--good)}.warning{background:#fff7e4;color:#6f4c00}label{display:block;margin-top:1rem;font-weight:750}input{display:block;width:100%;margin-top:.3rem;padding:.6rem;border:2px solid #78909f;border-radius:7px}.actions{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:1.2rem}.helpbox{border-top:1px solid var(--line);margin-top:1.1rem;padding-top:.8rem}.logpanel{margin-top:1rem;padding:.8rem;background:#10232d;color:#d8edf5;border-radius:10px}.logpanel h2{margin:0 0 .4rem;font-size:1rem}.logs{white-space:pre-wrap;word-break:break-word;max-height:150px;overflow:auto;font:13px/1.4 ui-monospace,monospace}footer{padding-bottom:2rem}.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:.5rem}@media(max-width:500px){body{font-size:17px}.card{padding:1rem}}
</style></head><body>
<a class="skip" href="#main">Skip to current step</a>
<header class="top"><div class="topin"><div class="brand">Care Portal</div><div class="tag">Private account recovery</div><nav class="progress" aria-label="Recovery progress"><ol id="progress"></ol></nav></div></header>
<main id="main" tabindex="-1"><div id="app" aria-live="polite">Preparing your private recovery space…</div></main>
<footer>Take your time. Your secure server-backed step is saved. <a href="#help" id="footer-help">Get help and safety advice</a></footer>
<script nonce="${nonce}">(()=>{"use strict";
/* [2] All dynamic values are placed with textContent; user input is never HTML. */
const app=document.getElementById("app"),progress=document.getElementById("progress"),storageKey="care-recovery-progress",tokenKey="care-recovery-token";
const steps=["1. Start","2. Approved channel","3. New password","4. Sign in","5. Privacy"];
let csrf="",current="start",message="",serverStage="anonymous",logs=[];
const storeGet=(k)=>{try{return sessionStorage.getItem(k)}catch{return null}};
const storeSet=(k,v)=>{try{sessionStorage.setItem(k,v)}catch{}};
const storeRemove=(k)=>{try{sessionStorage.removeItem(k)}catch{}};
const localGet=()=>{try{return localStorage.getItem(storageKey)}catch{return null}};
const localSet=v=>{try{localStorage.setItem(storageKey,v)}catch{}};
const localRemove=()=>{try{localStorage.removeItem(storageKey)}catch{}};
const clearStored=()=>{localRemove();storeRemove(tokenKey)};
const mapStage=v=>({start:"anonymous",channel:"channel",delivery:"recovery",verify:"recovery",password:"verified",success:"resetComplete",login:"resetComplete",mfa:"mfa",mfaExhausted:"mfaExhausted",privacy:"authenticated",confirmed:"authenticated"})[v]||"anonymous";
function save(){if(current!=="help")localSet(JSON.stringify({current,serverStage:mapStage(current),message}))}
function clear(n){while(n.firstChild)n.removeChild(n.firstChild)}
function el(t,p,...kids){const n=document.createElement(t);for(const[k,v]of Object.entries(p||{})){if(k==="class")n.className=v;else if(k==="onclick")n.addEventListener("click",v);else if(k==="value")n.value=v;else if(k==="type")n.type=v;else n.setAttribute(k,String(v))}for(const c of kids.flat())if(c!==null&&c!==undefined)n.append(c.nodeType?c:document.createTextNode(String(c)));return n}
const p=(x,c)=>el("p",c?{class:c}:{},x),button=(x,fn,secondary)=>el("button",{type:"button",class:secondary?"secondary":"",onclick:fn},x);
function card(title){return el("section",{class:"card"},el("h1",{},title))}
function notice(b){if(message)b.append(el("div",{class:"notice"},message))}
function addLog(x){console.log(x);logs.push(x)}
function api(path,body){return fetch(path,{method:body===undefined?"GET":"POST",credentials:"same-origin",headers:body===undefined?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body===undefined?undefined:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false,message:"We could not complete that step."}))}
async function restartRecovery(note){
 const d=await api("/api/recovery/abandon",{});
 if(d.ok){clearStored();serverStage="anonymous";current="start";message=note;render()}else{message=d.message;render()}
}
function abandonButton(){return button("Start recovery again",()=>restartRecovery("This recovery attempt was safely closed. You can start again when ready."),true)}
function tail(b,recovery=false){if(recovery)b.append(el("div",{class:"actions"},abandonButton()));b.append(el("div",{class:"helpbox"},p("Need a pause? You can return without losing a valid server-backed step.","quiet"),p("Need support? Use Help and safety advice below.","quiet")));return b}
function logPanel(){return el("aside",{class:"logpanel"},el("h2",{},"Logs"),el("div",{class:"logs"},logs.length?logs.join("\\n"):"No simulated messages yet."))}
function idx(){return({start:0,channel:1,delivery:1,verify:1,password:2,success:3,login:3,mfa:3,mfaExhausted:3,privacy:4,confirmed:4})[current]||0}
function renderProgress(){clear(progress);steps.forEach((s,i)=>progress.append(el("li",{class:i===idx()?"now":i<idx()?"done":""},s)))}
function invalid(d){if(!d.invalidRecovery)return false;clearStored();serverStage="anonymous";current="start";message=d.message;render();return true}
async function bootstrap(){
 const b=await api("/api/bootstrap");if(!b.ok){message="Your private recovery space could not be prepared. Refresh and try again.";render();return}csrf=b.csrf;
 const s=await api("/api/status");serverStage=s.stage||"anonymous";let saved={};try{saved=JSON.parse(localGet()||"{}")}catch{}
 if(s.recoveryExpired){clearStored();current="start";message="This recovery link has expired. Start recovery again when you are ready."}
 else if(serverStage==="channel"){current="channel";message="Your saved progress has been restored at the approved-channel step. Enter the secret you received, or ask us to send a new one."}
 else if(saved.current&&saved.serverStage===serverStage){current=saved.current;message=saved.message||""}
 else if(serverStage!=="anonymous"){current=({channel:"channel",recovery:"delivery",verified:"password",resetComplete:"success",mfa:"mfa",mfaExhausted:"mfaExhausted",authenticated:s.privacyAccepted?"confirmed":"privacy"})[serverStage]||"start";message="Your saved step has been restored."}
 const token=new URLSearchParams(location.search).get("token");if(location.pathname==="/recovery/verify"&&token&&/^[A-Za-z0-9_-]{40,100}$/.test(token)&&serverStage==="recovery"){storeSet(tokenKey,token);current="verify";message="Recovery link opened. Check the code below to continue."}render();
}
function startView(){const b=card("Reset your password");b.append(p("We will guide you one small step at a time."),el("div",{class:"next"},el("strong",{},"Next step: "),"enter the email address you use for your account."));notice(b);const f=el("form",{}),i=el("input",{type:"email",autocomplete:"email",required:"",maxlength:"160",id:"email"});f.append(el("label",{for:"email"},"Account email"),i,p("For privacy, we give the same message whether or not an account can be recovered.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Continue")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/recovery/start",{email:i.value});message=d.message;if(d.ok){serverStage="channel";current="channel";addLog("SIMULATED APPROVED-CHANNEL DELIVERY: authorization secret: "+d.authorizationSecret);addLog("Use this private authorization secret only on this Care Portal page.")}render()});b.append(f);return tail(b)}
function channelView(){
 const b=card("Confirm your approved recovery channel");
 b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"check the Logs panel for your private approved-channel authorization secret, then enter it here."));
 notice(b);
 const f=el("form",{}),i=el("input",{type:"text",autocomplete:"one-time-code",required:"",maxlength:"100",id:"channel"});
 f.append(el("label",{for:"channel"},"Approved-channel authorization secret"),i,p("The secret is simulated in your browser console and Logs panel. It is not displayed in this form.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Confirm channel")));
 f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/recovery/channel",{code:i.value.trim()});message=d.message;if(d.ok){serverStage="recovery";storeSet(tokenKey,d.token);addLog("SIMULATED RECOVERY DELIVERY: private reset code: "+d.token);addLog("SIMULATED RECOVERY DELIVERY: verification link: "+location.origin+"/recovery/verify?token="+d.token);current="delivery"}render()});
 const resend=button("Send the authorization secret again",async()=>{
   const d=await api("/api/recovery/channel/resend",{});
   message=d.message;
   if(d.ok){
     addLog("SIMULATED APPROVED-CHANNEL DELIVERY (RESENT): authorization secret: "+d.authorizationSecret);
     addLog("The earlier authorization secret is no longer valid. Use this new secret only on this Care Portal page.");
   }
   render();
 },true);
 b.append(f,el("div",{class:"actions"},resend),p("If you request another secret, the earlier one is safely replaced. Your recovery progress stays on this step.","hint"));
 return tail(b,true);
}
function deliveryView(){const b=card("Check your recovery message");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"open the simulated recovery link, or enter the code yourself."));notice(b);const t=storeGet(tokenKey),actions=el("div",{class:"actions"});if(t)actions.append(el("a",{href:"/recovery/verify?token="+encodeURIComponent(t)},"Open simulated recovery link"));actions.append(button("Enter a code manually",()=>{current="verify";save();render()},true));b.append(actions);return tail(b,true)}
function verifyView(){const b=card("Check your recovery code");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"paste or type the private code, then select Check code."));notice(b);const f=el("form",{}),i=el("input",{type:"text",autocomplete:"one-time-code",required:"",maxlength:"100",id:"code",placeholder:"Recovery code"}),t=storeGet(tokenKey);if(t)i.value=t;f.append(el("label",{for:"code"},"Recovery code"),i,p("Codes are private. Never share a password or code with unexpected callers.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Check code")));f.addEventListener("submit",async e=>{e.preventDefault();const entered=i.value.trim();storeSet(tokenKey,entered);const d=await api("/api/recovery/verify",{token:entered});if(invalid(d))return;message=d.message;if(d.ok){serverStage="verified";current="password";history.replaceState({},"","/")}render()});b.append(f);return tail(b,true)}
function passwordView(){const b=card("Choose a new password");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"create your new password, then save it."));notice(b);const f=el("form",{}),a=el("input",{type:"password",autocomplete:"new-password",required:"",maxlength:"200",id:"pw"}),c=el("input",{type:"password",autocomplete:"new-password",required:"",maxlength:"200",id:"pw2"});f.append(el("label",{for:"pw"},"New password"),a,el("label",{for:"pw2"},"Type it again"),c,p("At least 12 characters, uppercase, lowercase, number, symbol, and no spaces.","hint"),el("div",{class:"actions"},el("button",{type:"submit"},"Save new password")));f.addEventListener("submit",async e=>{e.preventDefault();if(a.value!==c.value){message="The two passwords do not match. Please type them again.";render();return}const d=await api("/api/recovery/password",{token:storeGet(tokenKey)||"",password:a.value});if(invalid(d))return;message=d.message;if(d.ok){storeRemove(tokenKey);serverStage="resetComplete";current="success"}render()});b.append(f);return tail(b,true)}
function successView(){const b=card("Password changed");b.append(el("div",{class:"notice"},"Your new password is ready to use."),el("div",{class:"actions"},button("Go to sign in",()=>{current="login";save();render()}),button("Restart password recovery",()=>restartRecovery("You can start a new password recovery when ready."),true)));return tail(b)}
function loginView(){const b=card("Sign in");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"enter your account email and password."));notice(b);const f=el("form",{}),e=el("input",{type:"email",autocomplete:"username",required:"",maxlength:"160",id:"le"}),pw=el("input",{type:"password",autocomplete:"current-password",required:"",maxlength:"200",id:"lp"});f.append(el("label",{for:"le"},"Account email"),e,el("label",{for:"lp"},"Password"),pw,el("div",{class:"actions"},el("button",{type:"submit"},"Sign in"),button("Reset password instead",()=>restartRecovery("Start password recovery when you are ready."),true)));f.addEventListener("submit",async x=>{x.preventDefault();const d=await api("/api/login",{email:e.value,password:pw.value});message=d.message;if(d.ok){addLog("SIMULATED MFA DELIVERY: one-time verification code: "+d.mfaCode);serverStage="mfa";current="mfa"}render()});b.append(f);return tail(b)}
function mfaView(){const b=card("One more safety check");b.append(el("div",{class:"next"},el("strong",{},"Next step: "),"enter the one-time verification code from the Logs panel."));notice(b);const f=el("form",{}),i=el("input",{type:"text",autocomplete:"one-time-code",required:"",maxlength:"6",id:"mfa"});f.append(el("label",{for:"mfa"},"One-time code"),i,el("div",{class:"actions"},el("button",{type:"submit"},"Verify and continue")));f.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/mfa",{code:i.value.trim()});message=d.message;if(d.ok){serverStage="authenticated";current="privacy"}else if(d.mfaExhausted){serverStage="mfaExhausted";current="mfaExhausted"}render()});b.append(f);return tail(b)}
function mfaExhaustedView(){const b=card("Sign-in check paused");b.append(el("div",{class:"notice warning"},"For your security, this one-time verification check is no longer active."),p("You can sign in again to receive a new code, or restart password recovery if you need it."),el("div",{class:"actions"},button("Sign in again",()=>{current="login";message="Sign in again when you are ready.";render()}),button("Restart password recovery",()=>restartRecovery("Start password recovery when you are ready."),true)));return tail(b)}
function privacyView(){const b=card("Privacy statement");b.append(el("div",{class:"notice"},"Authenticated account session active."),p("Hospital authorities need your acceptance of the updated privacy conditions before appointment support can continue."));notice(b);b.append(el("div",{class:"actions"},button("Accept privacy statement",async()=>{const d=await api("/api/privacy/accept",{});message=d.message;if(d.ok)current="confirmed";render()})));return tail(b)}
function confirmedView(){const b=card("Privacy statement accepted");b.append(el("div",{class:"notice"},"Confirmation recorded in this simulated authenticated session."),p("Hospital authorities can now continue with appointment support for your medication dosage review."));return tail(b)}
function helpView(){
 const b=card("Help and safety advice");
 b.append(
   p("You can pause and return to your saved progress while your secure session remains valid. For safety, recovery codes expire after 15 minutes and sessions expire after 24 hours. If either expires, you can request recovery again when you are ready."),
   el("h2",{},"Keep your account safe"),
   el("ul",{},el("li",{},"Only sign in on this Care Portal address."),el("li",{},"Never share your password or recovery code by email, phone, or message."),el("li",{},"Hospital staff will not ask you to read out a password.")),
   el("div",{class:"actions"},button("Return to my step",()=>{current=serverStage==="anonymous"?"start":({channel:"channel",recovery:"delivery",verified:"password",resetComplete:"success",mfa:"mfa",mfaExhausted:"mfaExhausted",authenticated:"privacy"})[serverStage]||"start";render()},true))
 );
 return b;
}
function render(){renderProgress();clear(app);const v=({start:startView,channel:channelView,delivery:deliveryView,verify:verifyView,password:passwordView,success:successView,login:loginView,mfa:mfaView,mfaExhausted:mfaExhaustedView,privacy:privacyView,confirmed:confirmedView,help:helpView})[current]||startView;app.append(v(),logPanel());save();document.getElementById("main").focus()}
document.getElementById("footer-help").addEventListener("click",e=>{e.preventDefault();current="help";render()});window.addEventListener("hashchange",()=>{if(location.hash==="#help"){current="help";render()}});bootstrap()})()</script></body></html>`;
}

async function handleApi(request: Request, path: string) {
  if (path === "/api/bootstrap" && request.method === "GET") {
    let session = getSession(request), cookie: string | undefined;
    if (!session) { session = createSession(); cookie = sessionCookie(session); }
    return json({ ok: true, csrf: session.csrf }, 200, cookie);
  }
  if (path === "/api/status" && request.method === "GET") {
    const session = getSession(request);
    if (!session) return json({ ok: true, stage: "anonymous", recoveryExpired: false });
    const recoveryExpired = expireRecoveryIfNeeded(session);
    return json({ ok: true, stage: session.stage, recoveryExpired, privacyAccepted: !!session.privacyAccepted });
  }

  // [1] Every state-changing endpoint requires same-origin request and session CSRF token.
  if (request.method !== "POST") return genericError(405);
  const session = csrfSession(request);
  if (!session) return genericError(403);

  let data: Record<string, unknown>;
  try { data = await requestData(request); } catch { return genericError(); }

  if (path === "/api/recovery/abandon") {
    if (session.stage !== "authenticated") clearRecovery(session);
    return json({ ok: true, message: "Recovery state cleared." });
  }

  if (path === "/api/recovery/start") {
    if (!isAllowedEmail(data.email) || !["anonymous", "channel", "mfaExhausted"].includes(session.stage)) return genericError();

    const authorizationSecret = randomToken(32);
    const normalizedEmail = (data.email as string).toLowerCase();
    session.stage = "channel";
    session.userId = normalizedEmail === INTERNAL_ACCOUNT.login ? INTERNAL_ACCOUNT.id : undefined;
    session.channelHash = digest(authorizationSecret);
    session.resetHash = undefined; session.resetExpires = undefined; session.resetUsed = false;
    session.channelAttempts = 0; session.channelLockedUntil = 0;
    session.resetVerifyAttempts = 0; session.resetVerifyLockedUntil = 0;

    await pause(RECOVERY_RESPONSE_DELAY);
    return json({
      ok: true,
      authorizationSecret,
      message: "If this account can be recovered, confirm the approved recovery channel next."
    });
  }

  /*
   [1][4] Resend is available only to this CSRF-authenticated recovery session
   while it remains at the approved-channel step. Replacing channelHash makes
   every prior authorization secret immediately invalid.
  */
  if (path === "/api/recovery/channel/resend") {
    if (session.stage !== "channel") return genericError();
    const authorizationSecret = randomToken(32);
    session.channelHash = digest(authorizationSecret);
    session.channelAttempts = 0;
    session.channelLockedUntil = 0;
    await pause(RECOVERY_RESPONSE_DELAY);
    return json({
      ok: true,
      authorizationSecret,
      message: "A new authorization secret is ready in the Logs panel. Your earlier secret is no longer valid."
    });
  }

  // [4] Bounded server-side authorization attempts. No account-existence branch is exposed.
  if (path === "/api/recovery/channel") {
    if (session.stage !== "channel") return genericError();
    if (session.channelLockedUntil > Date.now()) return lockedRecoveryError();

    const valid = typeof data.code === "string" && isToken(data.code) && !!session.channelHash &&
      safeEqual(digest(data.code), session.channelHash);

    if (!valid) {
      session.channelAttempts++;
      if (session.channelAttempts >= MAX_RECOVERY_ATTEMPTS) {
        session.channelAttempts = 0;
        session.channelLockedUntil = Date.now() + LOCK_TTL;
      }
      await pause(RECOVERY_RESPONSE_DELAY);
      return session.channelLockedUntil > Date.now() ? lockedRecoveryError() : genericError();
    }

    const resetToken = randomToken();
    session.stage = "recovery";
    session.channelHash = undefined;
    session.channelAttempts = 0;
    session.resetHash = digest(resetToken);
    session.resetExpires = Date.now() + RESET_TTL;
    session.resetUsed = false;
    session.resetVerifyAttempts = 0;
    session.resetVerifyLockedUntil = 0;

    await pause(RECOVERY_RESPONSE_DELAY);
    return json({
      ok: true,
      token: resetToken,
      message: "If this account can be recovered, a private recovery message is ready."
    });
  }

  if (path === "/api/recovery/verify") {
    if (expireRecoveryIfNeeded(session) || session.stage !== "recovery" || !session.resetHash || session.resetUsed) {
      return recoveryStateError(session);
    }
    if (session.resetVerifyLockedUntil > Date.now()) return lockedRecoveryError();
    const matches = isToken(data.token) && safeEqual(digest(data.token), session.resetHash);
    if (!matches) {
      session.resetVerifyAttempts++;
      if (session.resetVerifyAttempts >= MAX_RECOVERY_ATTEMPTS) {
        session.resetVerifyAttempts = 0;
        session.resetVerifyLockedUntil = Date.now() + LOCK_TTL;
        return lockedRecoveryError();
      }
      return json({ ok: false, incorrectToken: true, message: "That recovery code does not match. Please check it and try again." });
    }
    session.resetVerifyAttempts = 0;
    session.stage = "verified";
    return json({ ok: true, message: "Code checked. You can now choose a new password." });
  }

  if (path === "/api/recovery/password") {
    const problem = passwordProblem(data.password);
    if (problem) return json({ ok: false, message: problem });
    if (expireRecoveryIfNeeded(session) || session.stage !== "verified" ||
      !isToken(data.token) || !session.resetHash || session.resetUsed ||
      !safeEqual(digest(data.token), session.resetHash)) return recoveryStateError(session);

    if (session.userId === INTERNAL_ACCOUNT.id) {
      INTERNAL_ACCOUNT.passwordHash = await Bun.password.hash(data.password as string, { algorithm: "argon2id" });
    }
    session.resetUsed = true;
    session.resetHash = undefined;
    session.resetExpires = undefined;
    session.stage = "resetComplete";
    return json({ ok: true, message: "Your password has been changed securely." });
  }

  if (path === "/api/login") {
    if (!isAllowedEmail(data.email) || typeof data.password !== "string" || data.password.length > 200) return genericError();
    const key = digest((data.email as string).toLowerCase()), attempts = loginFailures.get(key) || { failures: 0, lockedUntil: 0 };
    if (attempts.lockedUntil > Date.now()) return genericError(429);
    const matchesEmail = (data.email as string).toLowerCase() === INTERNAL_ACCOUNT.login;
    let matchesPassword = false;
    try { matchesPassword = matchesEmail && await Bun.password.verify(data.password as string, INTERNAL_ACCOUNT.passwordHash); } catch {}
    if (!matchesPassword) {
      attempts.failures++;
      if (attempts.failures >= 5) { attempts.failures = 0; attempts.lockedUntil = Date.now() + LOCK_TTL; }
      loginFailures.set(key, attempts);
      return genericError();
    }
    loginFailures.delete(key);
    session.stage = "mfa";
    session.userId = INTERNAL_ACCOUNT.id;
    session.mfaAttempts = 0;
    session.mfaCode = MFA_CODE;
    return json({ ok: true, mfaCode: MFA_CODE, message: "Password accepted. Your one-time code is in the Logs panel." });
  }

  if (path === "/api/mfa") {
    if (session.stage !== "mfa" || typeof data.code !== "string" || !/^\d{6}$/.test(data.code)) return genericError();
    if (!session.mfaCode || !safeEqual(data.code, session.mfaCode)) {
      session.mfaAttempts++;
      if (session.mfaAttempts >= MAX_RECOVERY_ATTEMPTS) {
        session.mfaCode = undefined;
        session.mfaAttempts = 0;
        session.userId = undefined;
        session.stage = "mfaExhausted";
        return json({ ok: false, mfaExhausted: true, message: "For your security, this sign-in check has been paused. Sign in again or restart password recovery." });
      }
      return genericError();
    }
    session.stage = "authenticated";
    session.mfaCode = undefined;
    session.privacyAccepted = false;
    return json({ ok: true, message: "You are signed in. Review the privacy statement below." });
  }

  if (path === "/api/privacy/accept") {
    if (session.stage !== "authenticated" || !session.userId) return genericError(403);
    session.privacyAccepted = true;
    return json({ ok: true, message: "Privacy statement accepted. Appointment support may now continue." });
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
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery/verify")) {
      const nonce = randomToken(18), headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch {
    return new Response("Service unavailable", { status: 503, headers: baseHeaders() });
  }
}

const certPath = Bun.file("certs/cert.pem"), keyPath = Bun.file("certs/key.pem");
if (!(await certPath.exists()) || !(await keyPath.exists())) {
  console.error("HTTPS certificates are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

// [3] HTTPS listener, HSTS, CSP, Secure cookies, and no diagnostic responses.
Bun.serve({
  port: PORT, hostname: "localhost",
  tls: { cert: await certPath.text(), key: await keyPath.text() },
  fetch: handler,
});
console.log(`Care Portal securely listening at https://localhost:${PORT}`);
