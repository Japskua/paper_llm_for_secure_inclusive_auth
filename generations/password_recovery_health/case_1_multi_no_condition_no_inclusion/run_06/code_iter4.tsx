
const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

type RateRecord = { count: number; resetAt: number };
type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  /* A token-link session is restricted until its recovery code is verified. */
  pendingResetToken?: string;
  resetVerified: boolean;
  passwordReplaced: boolean;
  mfaComplete: boolean;
  privacyAccepted: boolean;
  credentialHash?: string;
};

type ResetToken = {
  expiresAt: number;
  used: boolean;
  attempts: number;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();
const rateLimits = new Map<string, RateRecord>();
const encoder = new TextEncoder();

/* Requirements 1, 3, 4: cryptographically random server-side session, CSRF, and token values. */
function secureToken(bytes = 32): string {
  return crypto.getRandomValues(new Uint8Array(bytes)).toBase64({
    alphabet: "base64url",
    omitPadding: true,
  });
}

function secureHeaders(nonce?: string): Headers {
  const csp = [
    "default-src 'self'",
    `script-src 'nonce-${nonce || "none"}'`,
    `style-src 'nonce-${nonce || "none"}'`,
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": csp,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0",
  });
}

function json(data: unknown, status = 200, extraHeaders: HeadersInit = {}): Response {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store, max-age=0");
  return new Response(JSON.stringify(data), { status, headers });
}

function securedResponse(response: Response): Response {
  const headers = secureHeaders();
  response.headers.forEach((value, key) => headers.set(key, value));
  return new Response(response.body, { status: response.status, headers });
}

/* Requirement task: malformed percent encoding is ignored rather than throwing in cookie parsing. */
function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};

  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;

    const name = part.slice(0, index).trim();
    const rawValue = part.slice(index + 1).trim();
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(name) || rawValue.length === 0) continue;

    try {
      const value = decodeURIComponent(rawValue);
      /* Cookie values used by this application are opaque base64url tokens only. */
      if (/^[A-Za-z0-9_-]{1,128}$/.test(value)) output[name] = value;
    } catch {
      /* Invalid cookie encoding is untrusted input and is deliberately ignored. */
    }
  }
  return output;
}

function sessionFor(request: Request): Session | undefined {
  const id = parseCookies(request).recovery_session;
  return id ? sessions.get(id) : undefined;
}

function createSession(pendingResetToken?: string): Session {
  const session: Session = {
    id: secureToken(32),
    csrf: secureToken(32),
    createdAt: Date.now(),
    pendingResetToken,
    resetVerified: false,
    passwordReplaced: false,
    mfaComplete: false,
    privacyAccepted: false,
  };
  sessions.set(session.id, session);
  return session;
}

function sessionCookie(session: Session): string {
  /* Requirements 1, 3: HttpOnly session cookie with TLS-only and strict same-site protection. */
  return `recovery_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}

function timingSafeEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let difference = 0;
  for (let i = 0; i < aa.length; i++) difference |= aa[i] ^ bb[i];
  return difference === 0;
}

function validCsrf(request: Request, session: Session | undefined): boolean {
  const received = request.headers.get("x-csrf-token") || "";
  return !!session && received.length === session.csrf.length && timingSafeEqual(received, session.csrf);
}

/* Requirement 4: in-memory throttling uses opaque server-generated identifiers only. */
function consumeRateLimit(key: string, maximum: number, windowMs: number): boolean {
  const now = Date.now();
  const old = rateLimits.get(key);
  if (!old || old.resetAt <= now) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  old.count++;
  return old.count <= maximum;
}

function parseJsonObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return parseJsonObject(await request.json());
  } catch {
    return null;
  }
}

function textField(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

function validRecoveryIdentifier(value: string): boolean {
  return /^[A-Za-z0-9@._ -]{3,160}$/.test(value);
}

function validResetToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{40,100}$/.test(value);
}

function strongPassword(value: string): boolean {
  return value.length >= 12 && value.length <= 128 && !/\s/.test(value) &&
    /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

function cleanExpiredState(): void {
  const now = Date.now();
  for (const [token, state] of resetTokens) {
    if (state.expiresAt < now) resetTokens.delete(token);
  }
  for (const [id, session] of sessions) {
    if (session.createdAt + 30 * 60 * 1000 < now) sessions.delete(id);
  }
}

function usableToken(token: string | null): boolean {
  if (!token || !validResetToken(token)) return false;
  const state = resetTokens.get(token);
  return !!state && !state.used && state.expiresAt >= Date.now() && state.attempts <= 5;
}

/* Requirements 1, 4: every state-changing endpoint validates the unique session CSRF token. */
function requireSessionAndCsrf(request: Request): { session?: Session; failure?: Response } {
  const session = sessionFor(request);
  if (!session) {
    return { failure: json({ message: "Your secure session has ended. Please restart recovery." }, 401) };
  }
  if (!validCsrf(request, session)) {
    return { failure: json({ message: "This request could not be verified. Refresh the page and try again." }, 403) };
  }
  return { session };
}

async function apiRecovery(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const session = auth.session!;

  /* A session created by a reset link is intentionally limited to verification. */
  if (session.pendingResetToken) {
    return json({ message: "Confirm the recovery code in this secure recovery session." }, 403);
  }

  const body = await requestBody(request);
  const identifier = textField(body?.identifier, 160);
  if (!identifier || !validRecoveryIdentifier(identifier)) {
    return json({ message: "Enter a valid email address or recovery reference." }, 400);
  }
  if (!consumeRateLimit(`recovery:${session.id}`, 3, 15 * 60 * 1000)) {
    return json({ message: "Please wait before requesting another recovery message." }, 429);
  }

  const token = secureToken(32);
  resetTokens.set(token, {
    expiresAt: Date.now() + 10 * 60 * 1000,
    used: false,
    attempts: 0,
  });

  return json({
    message: "If the account can be recovered, a secure recovery message has been prepared.",
    testToken: token,
  });
}

async function apiVerifyToken(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const session = auth.session!;
  const body = await requestBody(request);
  const token = textField(body?.token, 100);

  if (!token || !validResetToken(token)) {
    return json({ message: "That recovery code is not valid. Check the code and try again." }, 400);
  }

  /* A link-established session may verify only the token that established it. */
  if (session.pendingResetToken && !timingSafeEqual(token, session.pendingResetToken)) {
    return json({ message: "That recovery code is not valid or has expired." }, 400);
  }

  if (!consumeRateLimit(`verify:${session.id}`, 6, 10 * 60 * 1000)) {
    return json({ message: "Too many code attempts. Request a new recovery message later." }, 429);
  }

  const state = resetTokens.get(token);
  if (!state) {
    return json({ message: "That recovery code is not valid or has expired." }, 400);
  }

  state.attempts++;
  if (state.attempts > 5 || state.used || state.expiresAt < Date.now()) {
    resetTokens.delete(token);
    return json({ message: "That recovery code has expired or can no longer be used. Request a new one." }, 400);
  }

  /* Requirements 3, 4: token is single-use, authorization is server-side, and CSRF remains mandatory. */
  state.used = true;
  resetTokens.delete(token);
  session.pendingResetToken = undefined;
  session.resetVerified = true;
  session.passwordReplaced = false;
  session.mfaComplete = false;
  session.privacyAccepted = false;
  return json({ message: "Recovery code confirmed." });
}

async function apiPassword(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const session = auth.session!;

  if (!session.resetVerified) {
    return json({ message: "Confirm a newly issued recovery code before creating a password." }, 403);
  }

  const body = await requestBody(request);
  const password = textField(body?.password, 128);
  const confirmation = textField(body?.confirmation, 128);
  if (!password || !confirmation || password !== confirmation) {
    return json({ message: "The password entries must match." }, 400);
  }
  if (!strongPassword(password)) {
    return json({ message: "Use 12 or more characters with uppercase, lowercase, a number, and a symbol. Do not use spaces." }, 400);
  }

  /*
   * Task / Requirement 1, 4: atomically consume the recovery authorization
   * before the asynchronous hash operation. Concurrent password requests now
   * see resetVerified as false; failed hashing deliberately does not restore it.
   */
  session.resetVerified = false;
  session.pendingResetToken = undefined;

  /* Requirement 4: bcrypt only; plaintext is never retained. */
  session.credentialHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
  session.passwordReplaced = true;

  return json({ message: "Password updated.", demoMfaCode: "246810" });
}

async function apiMfa(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const session = auth.session!;
  if (!session.passwordReplaced) {
    return json({ message: "Create a new password before confirming the security code." }, 403);
  }

  const body = await requestBody(request);
  const code = textField(body?.code, 12);
  if (!code || !/^\d{6}$/.test(code)) {
    return json({ message: "Enter the six-digit security code." }, 400);
  }
  if (!consumeRateLimit(`mfa:${session.id}`, 5, 10 * 60 * 1000)) {
    return json({ message: "Too many incorrect attempts. Restart recovery later." }, 429);
  }
  if (code !== "246810") {
    return json({ message: "That security code was not accepted." }, 400);
  }

  session.mfaComplete = true;
  return json({ message: "Security code confirmed." });
}

async function apiPrivacy(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const body = await requestBody(request);
  if (!auth.session!.mfaComplete || body?.accepted !== true) {
    return json({ message: "Sign-in verification is required before accepting the privacy conditions." }, 403);
  }

  auth.session!.privacyAccepted = true;
  return json({ message: "Privacy conditions accepted." });
}

async function apiLogin(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  if (!consumeRateLimit(`login:${auth.session!.id}`, 5, 15 * 60 * 1000)) {
    return json({ message: "Too many sign-in attempts. Please wait before trying again." }, 429);
  }
  return json({ message: "Direct sign-in is unavailable during this recovery demonstration." }, 403);
}

function page(session: Session): Response {
  const nonce = secureToken(18);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Set-Cookie", sessionCookie(session));

  /* Requirement 2: all dynamic browser content uses textContent and DOM APIs, never HTML injection. */
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--blue:#084d89;--dark:#063962;--ink:#17212b;--muted:#53616e;--line:#c9d3dc;--soft:#eff6fa;--danger:#9a260f;--ok:#155b37}*{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;color:var(--ink);background:#f4f7f9;line-height:1.5}header{background:var(--blue);color:#fff;border-bottom:5px solid #77bce8}.header-inner,main,footer{max-width:760px;margin:auto;padding-left:24px;padding-right:24px}.header-inner{padding-top:22px;padding-bottom:20px}.brand{margin:0;font-size:1.35rem;font-weight:700}.brand span{display:block;font-size:.91rem;font-weight:400;margin-top:2px}main{padding-top:28px;padding-bottom:30px}.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:28px;box-shadow:0 2px 7px #17212b12}h1{font-size:1.65rem;line-height:1.22;margin:0 0 12px}h2{font-size:1.06rem;margin:22px 0 7px}p{margin:0 0 14px}label{display:block;font-weight:bold;margin:18px 0 6px}input{width:100%;padding:12px;font:inherit;border:2px solid #8092a1;border-radius:4px}input:focus{outline:3px solid #a9d9f5;outline-offset:1px;border-color:var(--blue)}button{margin-top:20px;padding:12px 18px;color:#fff;background:var(--blue);border:0;border-radius:4px;cursor:pointer;font:inherit;font-weight:bold}button:hover{background:var(--dark)}button:disabled{opacity:.6;cursor:wait}.notice,.warning{padding:14px;margin:18px 0;background:var(--soft);border-left:5px solid var(--blue)}.warning{margin:20px 0 0;background:#fff8e9;border-left-color:#b56d00}.privacy-content{padding:14px;margin:18px 0;background:#f7fafc;border:1px solid var(--line);border-radius:4px}.privacy-content h2{margin:0 0 8px}.privacy-content ul{margin:8px 0 0;padding-left:22px}.status{min-height:24px;margin-top:14px;font-weight:bold}.status.error{color:var(--danger)}.status.ok{color:var(--ok)}.check-row{display:flex;gap:10px;align-items:flex-start;margin-top:18px}.check-row input{width:auto;margin-top:5px}.logs{margin-top:24px;background:#13202b;color:#d8f0ff;border-radius:6px;padding:15px}.logs h2{margin:0 0 8px;color:#fff}#log-output{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:150px;overflow:auto}footer{color:var(--muted);font-size:.88rem;padding-bottom:28px}@media(max-width:550px){.card{padding:21px}.header-inner,main,footer{padding-left:16px;padding-right:16px}}
</style>
</head>
<body>
<header><div class="header-inner"><p class="brand">Hospital patient portal <span>Secure account recovery</span></p></div></header>
<main>
<section class="card" aria-labelledby="screen-title"><div id="app" aria-live="polite"></div></section>
<section class="logs" aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><pre id="log-output">Ready. Simulated delivery events appear here.</pre></section>
</main>
<footer>Use only the verified <strong>https://localhost</strong> address. This demonstration does not contact external services.</footer>
<script nonce="${nonce}">
"use strict";
const BOOT={csrf:"${session.csrf}"};
const app=document.getElementById("app");
const logOutput=document.getElementById("log-output");
let deliveredToken="";

function log(message){console.log(message);logOutput.textContent+="\\n"+message;logOutput.scrollTop=logOutput.scrollHeight}
function element(tag,text,attrs){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(attrs)Object.entries(attrs).forEach(function(e){if(e[0]==="className")n.className=e[1];else n.setAttribute(e[0],e[1])});return n}
function title(text){return element("h1",text,{id:"screen-title"})}
function paragraph(text){return element("p",text)}
function statusBox(){return element("p","",{className:"status",role:"alert"})}
function setStatus(node,message,bad){node.textContent=message;node.className="status "+(bad?"error":"ok")}
function button(text){return element("button",text,{type:"submit"})}
function clear(nodes){app.replaceChildren.apply(app,nodes)}
function safety(){const a=element("aside",undefined,{className:"warning","aria-label":"Account safety guidance"});a.append(element("strong","Stay safe: "),document.createTextNode("Hospital staff will never ask for your password or security code by email, phone, or text. Check that the address begins with https://localhost before continuing."));return a}
function input(labelText,type,name,autocomplete,max){const label=element("label",labelText,{for:name});const field=element("input",undefined,{id:name,name:name,type:type,autocomplete:autocomplete,maxlength:String(max),required:""});return{label:label,field:field}}
async function api(path,payload){try{const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":BOOT.csrf},credentials:"same-origin",body:JSON.stringify(payload)});const data=await r.json().catch(function(){return{message:"A secure response could not be read."}});return{ok:r.ok,data:data}}catch{return{ok:false,data:{message:"A secure connection could not be completed. Please try again."}}}}

function showRequest(){
 const form=element("form"),f=input("Email address or recovery reference","text","identifier","username",160),status=statusBox();
 f.field.setAttribute("pattern","[A-Za-z0-9@._ -]{3,160}");
 form.append(f.label,f.field,paragraph("Enter the email address or recovery reference associated with your account."),button("Send recovery message"),status);
 form.addEventListener("submit",async function(e){e.preventDefault();const value=f.field.value.trim();if(!/^[A-Za-z0-9@._ -]{3,160}$/.test(value)){setStatus(status,"Enter a valid email address or recovery reference.",true);return}const b=form.querySelector("button");b.disabled=true;const r=await api("/api/recovery",{identifier:value});b.disabled=false;if(!r.ok){setStatus(status,r.data.message,true);return}deliveredToken=r.data.testToken;const link=location.origin+location.pathname+"?token="+encodeURIComponent(deliveredToken);log("SIMULATED RECOVERY DELIVERY: secure code "+deliveredToken+" (valid for 10 minutes; test use only).");log("SIMULATED RECOVERY LINK: "+link);showDelivery()});
 clear([title("Recover your account"),paragraph("Start a secure password recovery request. For privacy, the same confirmation is shown for every request."),form,safety()]);
}
function showDelivery(){const next=element("button","Enter recovery code");next.type="button";next.addEventListener("click",showVerify);clear([title("Check your recovery message"),paragraph("If your account can be recovered, a secure message has been prepared. It contains a short-lived recovery link and code."),element("div","For this local demonstration, the simulated delivery is printed only in the browser Logs panel and browser console.",{className:"notice"}),next,safety()])}
function showVerify(){
 const form=element("form"),f=input("Recovery code","text","recovery-code","one-time-code",100),status=statusBox();
 f.field.setAttribute("spellcheck","false");f.field.value=deliveredToken||new URLSearchParams(location.search).get("token")||"";
 form.append(f.label,f.field,paragraph("You may use the recovery link or manually enter its code. Codes expire after 10 minutes and work once."),button("Confirm recovery code"),status);
 form.addEventListener("submit",async function(e){e.preventDefault();const token=f.field.value.trim();if(!/^[A-Za-z0-9_-]{40,100}$/.test(token)){setStatus(status,"Enter a valid recovery code.",true);return}const b=form.querySelector("button");b.disabled=true;const r=await api("/api/verify-token",{token:token});b.disabled=false;if(!r.ok){setStatus(status,r.data.message,true);return}history.replaceState({},"",location.pathname);log("Recovery code verified in this secure session.");showPassword()});
 clear([title("Confirm recovery code"),form,safety()]);
}
function showPassword(){
 const form=element("form"),a=input("New password","password","new-password","new-password",128),b=input("Confirm new password","password","confirm-password","new-password",128),status=statusBox();
 form.append(a.label,a.field,b.label,b.field,paragraph("Use at least 12 characters with uppercase and lowercase letters, a number, and a symbol. Do not use spaces."),button("Update password"),status);
 form.addEventListener("submit",async function(e){e.preventDefault();if(a.field.value!==b.field.value){setStatus(status,"The password entries must match.",true);return}const r=await api("/api/password",{password:a.field.value,confirmation:b.field.value});if(!r.ok){setStatus(status,r.data.message,true);return}log("SIMULATED MFA DELIVERY: security code "+r.data.demoMfaCode+" (test code only).");a.field.value="";b.field.value="";showMfa()});
 clear([title("Create a strong password"),form,safety()]);
}
function showMfa(){
 const form=element("form"),f=input("Six-digit security code","text","mfa-code","one-time-code",6),status=statusBox();
 f.field.setAttribute("inputmode","numeric");f.field.setAttribute("pattern","\\\\d{6}");
 form.append(f.label,f.field,paragraph("A second check protects your account. In this local demonstration, the code is in the Logs panel."),button("Verify security code"),status);
 form.addEventListener("submit",async function(e){e.preventDefault();const code=f.field.value.trim();if(!/^\\d{6}$/.test(code)){setStatus(status,"Enter the six-digit security code.",true);return}const r=await api("/api/mfa",{code:code});if(!r.ok){setStatus(status,r.data.message,true);return}log("MFA verification completed.");showPrivacy()});
 clear([title("Verify your identity"),form,safety()]);
}
function privacyConditions(){
 const content=element("section",undefined,{className:"privacy-content","aria-labelledby":"privacy-summary-title"});
 const heading=element("h2","Privacy conditions summary",{id:"privacy-summary-title"});
 const intro=paragraph("These updated conditions explain how the hospital uses account information when processing an appointment request.");
 const list=document.createElement("ul");
 ["We use your account and contact details to verify your identity and arrange care.","Authorized hospital staff may access only the information needed to process your appointment and meet legal care obligations.","We protect information with access controls and retain it only for the periods required by healthcare and records laws.","You may ask the hospital privacy office about access, correction, or concerns regarding your information."].forEach(function(item){list.append(element("li",item))});
 content.append(heading,intro,list);
 return content;
}
function showPrivacy(){
 const form=element("form"),check=element("input",undefined,{type:"checkbox",id:"privacy-check",required:""}),label=element("label","I have read and accept the updated privacy conditions.",{for:"privacy-check"}),row=element("div",undefined,{className:"check-row"}),status=statusBox();
 label.style.margin="0";row.append(check,label);
 form.append(paragraph("Updated privacy conditions allow hospital authorities to process the appointment request after your verified sign-in."),privacyConditions(),element("div","Your acceptance is protected by your authenticated recovery session. No patient or account identifier is shown on this page.",{className:"notice"}),row,button("Accept privacy conditions"),status);
 form.addEventListener("submit",async function(e){e.preventDefault();if(!check.checked){setStatus(status,"Please confirm that you accept the privacy conditions.",true);return}const r=await api("/api/privacy",{accepted:true});if(!r.ok){setStatus(status,r.data.message,true);return}log("Privacy conditions accepted in authenticated session.");showComplete()});
 clear([title("Updated privacy conditions"),form,safety()]);
}
function showComplete(){const restart=element("button","Start over");restart.type="button";restart.addEventListener("click",function(){location.href=location.pathname});clear([title("Recovery complete"),paragraph("Your password has been updated, identity verification is complete, and the updated privacy conditions have been accepted."),element("div","You may now return to the hospital appointment process. This recovery demonstration does not make an appointment.",{className:"notice"}),restart,safety()])}
if(new URLSearchParams(location.search).get("token"))showVerify();else showRequest();
</script>
</body>
</html>`;

  return new Response(html, { headers });
}

/* Task: generic non-debug error response with the same protective headers. */
function genericErrorResponse(): Response {
  const headers = secureHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({ message: "The secure service is temporarily unavailable. Please try again." }), {
    status: 500,
    headers,
  });
}

async function handle(request: Request): Promise<Response> {
  cleanExpiredState();
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/") {
    const suppliedToken = url.searchParams.get("token");
    let session = sessionFor(request);

    /*
     * Task: a valid reset link can start a new browser session. The opaque token
     * is not consumed by GET; it establishes a CSRF-protected restricted session
     * which must still POST the code successfully before password authorization.
     */
    if (usableToken(suppliedToken)) {
      if (!session) session = createSession(suppliedToken!);
      else if (!session.resetVerified && !session.passwordReplaced) session.pendingResetToken = suppliedToken!;
    } else if (!session) {
      session = createSession();
    }

    return page(session);
  }

  if (request.method === "POST") {
    let result: Response | undefined;
    if (url.pathname === "/api/recovery") result = await apiRecovery(request);
    else if (url.pathname === "/api/verify-token") result = await apiVerifyToken(request);
    else if (url.pathname === "/api/password") result = await apiPassword(request);
    else if (url.pathname === "/api/mfa") result = await apiMfa(request);
    else if (url.pathname === "/api/privacy") result = await apiPrivacy(request);
    else if (url.pathname === "/api/login") result = await apiLogin(request);
    if (result) return securedResponse(result);
  }

  return securedResponse(json({ message: "Not found." }, 404));
}

/* Task: complete HTTPS request boundary; no stack trace or internal error reaches clients. */
async function safeHandle(request: Request): Promise<Response> {
  try {
    return await handle(request);
  } catch {
    return genericErrorResponse();
  }
}

const certificatesPresent = await Bun.file(CERT_PATH).exists() && await Bun.file(KEY_PATH).exists();
if (!certificatesPresent) {
  /* Requirement 3: fail closed; never serve the portal over unsecured HTTP. */
  console.error("TLS certificate files are unavailable. Secure portal not started.");
  process.exit(1);
}

/* Requirement 3: TLS server uses supplied mkcert material. */
Bun.serve({
  port: HTTPS_PORT,
  tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) },
  fetch: safeHandle,
});

/* Requirement 3: HTTP listener permits only the fixed-host HTTPS redirect. */
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    try {
      const incoming = new URL(request.url);
      const headers = secureHeaders();
      headers.set("Location", `https://localhost:${HTTPS_PORT}${incoming.pathname}${incoming.search}`);
      return new Response(null, { status: 308, headers });
    } catch {
      return genericErrorResponse();
    }
  },
});

console.log(`Secure recovery portal: https://localhost:${HTTPS_PORT} (HTTP redirect: ${HTTP_PORT})`);
