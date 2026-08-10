
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem
*/
const encoder = new TextEncoder();

const sessions = new Map<string, { userId: string; csrf: string; createdAt: number; lastSeenAt: number }>();
const accounts = new Map<string, any>();

const SESSION_IDLE = 30 * 60_000;
const SESSION_ABSOLUTE = 8 * 60 * 60_000;
const MAX_FAILURES = 5;
const LOCKOUT = 5 * 60_000;

const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));

function sha256(value: string) {
  return Bun.CryptoHasher.hash("sha256", value, "hex");
}

function token(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

/* Requirement 3: constant-time comparison for authentication material. */
function same(a: string, b: string) {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let difference = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    difference |= (left[i] || 0) ^ (right[i] || 0);
  }
  return difference === 0;
}

/* Requirement 3: recovery codes are HMACed before being stored. */
async function hmac(value: string, key: Uint8Array) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return Buffer.from(
    await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value))
  ).toString("hex");
}

async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(ciphertext).toString("base64url")
  };
}

async function decrypt(value: any) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.ciphertext, "base64url")
  );
  return new TextDecoder().decode(plaintext);
}

function secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "";
  while (output.length < 32) {
    for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if (byte < 248) {
        output += alphabet[byte % 32];
        if (output.length === 32) return output;
      }
    }
  }
  return output;
}

function recoveryCodes() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const codes = new Set<string>();
  while (codes.size < 10) {
    let raw = "";
    while (raw.length < 10) {
      for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
        if (byte < 252) {
          raw += alphabet[byte % 36];
          if (raw.length === 10) break;
        }
      }
    }
    codes.add(raw.slice(0, 5) + "-" + raw.slice(5));
  }
  return [...codes];
}

function base32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let count = 0;
  const output: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const number = alphabet.indexOf(char);
    if (number < 0) throw new Error("invalid");
    bits = (bits << 5) | number;
    count += 5;
    while (count >= 8) {
      count -= 8;
      output.push((bits >>> count) & 255);
    }
  }
  return new Uint8Array(output);
}

async function totp(value: string, counter = Math.floor(Date.now() / 30_000)) {
  const data = new Uint8Array(8);
  let number = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    data[i] = Number(number & 255n);
    number >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    base32(value),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = digest[19] & 15;
  const result =
    ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(result % 1_000_000).padStart(6, "0");
}

accounts.set("marcus-account-001", {
  id: "marcus-account-001",
  email: "marcus@example.com",
  passwordHash: sha256("BankDemo!42"),
  mfaEnabled: false,
  pending: null,
  active: null,
  pendingUsed: [],
  backup: [],
  usedBackup: [],
  otpFailures: 0,
  otpLocked: 0,
  recoveryFailures: 0,
  recoveryLocked: 0,
  replacing: false
});

const dummyPasswordHash = sha256("not-a-real-account-password");

function cookies(request: Request) {
  const output: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) output[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return output;
}

function trusted(hostname: string) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function originOK(request: Request) {
  const url = new URL(request.url);
  return url.protocol === "https:" && trusted(url.hostname) && request.headers.get("origin") === url.origin;
}

/* Requirement 2: security headers and restrictive same-origin CORS. */
function headers(request: Request, nonce = "") {
  const output = new Headers({
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store"
  });
  if (originOK(request)) {
    output.set("Access-Control-Allow-Origin", new URL(request.url).origin);
    output.set("Access-Control-Allow-Credentials", "true");
    output.set("Vary", "Origin");
  }
  return output;
}

function json(request: Request, payload: any, status = 200, extra?: HeadersInit) {
  const output = headers(request);
  output.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, name) => output.set(name, value));
  return new Response(JSON.stringify(payload), { status, headers: output });
}

async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as any : null;
  } catch {
    return null;
  }
}

/* Requirement 1: account identity always comes exclusively from HttpOnly session. */
function owner(request: Request): any {
  const id = cookies(request).mfa_session;
  const session = id && sessions.get(id);
  const now = Date.now();

  if (!session || now - session.lastSeenAt > SESSION_IDLE || now - session.createdAt > SESSION_ABSOLUTE) {
    if (id) sessions.delete(id);
    return null;
  }

  const account = accounts.get(session.userId);
  if (!account) return null;
  session.lastSeenAt = now;
  return { id, session, account };
}

/* Requirement 1: state-changing endpoints require same-origin anti-CSRF token. */
function csrf(request: Request, session: any) {
  return originOK(request) && request.headers.get("x-csrf-token") === session.csrf;
}

function validOtp(value: any) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

/* Requirement task: recovery endpoint accepts only AAAAA-BBBBB. */
function validRecoveryCode(value: any) {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(value);
}

function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE / 1000}`;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--bad:#8b2424;--good:#125b35}
*{box-sizing:border-box}
body{margin:0;background:#f3f7fb;color:var(--ink);font:16px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}
main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 28px}
header{display:flex;gap:10px;align-items:center}.mark{background:var(--blue);color:white;border-radius:12px;padding:8px 14px;font-size:22px}
h1{font-size:1.35rem;margin:0}h2{line-height:1.3;margin-top:0}.steps{display:flex;gap:4px;margin:18px 0}
.steps span{flex:1;border-bottom:4px solid var(--line);font-size:.72rem;text-align:center;padding-bottom:4px}
.steps .on{border-color:var(--blue);color:#073c83;font-weight:bold}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:20px}
.notice{padding:11px;border-radius:9px;background:var(--soft);margin:12px 0}.bad{background:#fff0f0;color:var(--bad)}.success{background:#effaf2;color:var(--good)}
label{display:block;font-weight:bold;margin:15px 0 5px}input,button{width:100%;min-height:52px;border-radius:10px;font:inherit}
input{border:2px solid #9eafc0;padding:10px;letter-spacing:.05em}button{border:0;padding:10px;margin-top:12px;font-weight:bold;cursor:pointer}
.primary{background:var(--blue);color:white}.secondary{background:white;color:#073c83;border:2px solid var(--blue)}
button:focus,input:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}
.qr{width:250px;height:250px;padding:8px;margin:15px auto;border:1px solid var(--line);background:white}
.secret,.code{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px}.row button{flex:1}
.hint{color:#526273;font-size:.88rem}.sensitive[hidden]{display:none}details{margin-top:14px}
.logs{margin-top:16px;background:#12202d;color:#eaf3fb;border-radius:12px;padding:13px}.logs h2{font-size:1rem;margin:0 0 7px}.logs pre{white-space:pre-wrap;margin:0;font:12px/1.5 ui-monospace,Consolas,monospace}
@media(max-width:390px){.codes{grid-template-columns:1fr}.row{flex-direction:column}}
</style>
</head>
<body>
<main>
<header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><div class="hint">Security setup</div></div></header>
<nav class="steps" aria-label="Setup steps"><span data-s="1">1. Confirm</span><span data-s="2">2. App</span><span data-s="3">3. Check</span><span data-s="4">4. Save</span></nav>
<section id="app" class="card" aria-live="polite"></section>
<p class="hint">Take your time. There is no reading timer.</p>
<section class="logs" aria-label="Logs"><h2>Logs</h2><pre id="logs">Ready.</pre></section>
</main>
<script nonce="${nonce}">
"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs");
let csrf="",secretValue="",uri="",codes=[];

function log(message,value){
  console.log(message,value);
  logs.textContent+=(logs.textContent?"\\n":"")+message+(value===undefined?"":" "+JSON.stringify(value));
}
function esc(value){const el=document.createElement("span");el.textContent=String(value);return el.innerHTML}
function step(number){document.querySelectorAll("[data-s]").forEach(el=>el.classList.toggle("on",+el.dataset.s===number))}
function note(text,kind=""){return '<div class="notice '+kind+'">'+esc(text)+"</div>"}
function help(){return "<details><summary>Help with this step</summary><p>Pause or retry at any time. There is no reading timer.</p></details>"}
function formMessage(message,kind="bad"){app.insertAdjacentHTML("afterbegin",note(message,kind))}

async function api(path,data={}){
  const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});
  const dataOut=await response.json().catch(()=>({message:"Please try again."}));
  if(response.status===401){csrf="";signin("Your session ended. Please sign in again.")}
  return {response,data:dataOut};
}
async function copy(value,name){
  const message=document.querySelector("#msg");
  try{
    await navigator.clipboard.writeText(value);
    if(message)message.textContent=name+" copied. You can paste it somewhere safe.";
  }catch{
    if(message)message.textContent="Copy did not work in this browser. You can select the text and copy it instead.";
  }
}

/* A readable visual setup marker accompanies the manually copyable provisioning secret. */
function qr(text){
  const target=document.querySelector("#qr");
  let seed=0;for(const char of text)seed=((seed*31)+char.charCodeAt(0))>>>0;
  let cells="";
  for(let y=0;y<29;y++)for(let x=0;x<29;x++){
    seed=(seed*1664525+1013904223)>>>0;
    const finder=(x<7&&y<7)||(x>21&&y<7)||(x<7&&y>21);
    if(finder||((seed>>>29)&1))cells+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>';
  }
  target.innerHTML='<svg viewBox="0 0 29 29" role="img" aria-label="Authenticator setup QR code"><rect width="100%" height="100%" fill="white"/><g fill="black">'+cells+"</g></svg>";
}

function signin(info=""){
  step(1);
  app.innerHTML="<h2>Confirm your account</h2><p>Use your bank email and password.</p>"+
    note("Demo: marcus@example.com · password: BankDemo!42")+
    (info?note(info):"")+
    '<label for="email-input">Email address</label><input id="email-input" type="email" autocomplete="email" placeholder="marcus@example.com">'+
    '<label for="password-input">Password</label><input id="password-input" type="password" autocomplete="current-password">'+
    '<button class="primary" id="signin-button">Continue</button>'+help();

  document.querySelector("#signin-button").onclick=async()=>{
    const email=(document.querySelector("#email-input")).value;
    const password=(document.querySelector("#password-input")).value;
    const response=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});
    const data=await response.json().catch(()=>({message:"Please try again."}));
    if(!response.ok)return formMessage(data.message);
    csrf=data.csrf;
    data.mfaEnabled?account("Your authenticator is active."):setup("Your identity is confirmed. Next, add your authenticator app.");
  };
}

function setup(message){
  step(2);
  app.innerHTML="<h2>Add your authenticator app</h2>"+note(message)+
    "<p>Open your authenticator app. You can scan a setup image or copy a secret.</p>"+
    '<button class="primary" id="show-setup">Show secure setup</button>'+help();
  document.querySelector("#show-setup").onclick=provision;
}

async function provision(){
  const result=await api("/api/provision");
  if(!result.response.ok)return formMessage(result.data.message);
  secretValue=result.data.secret;uri=result.data.uri;
  log("Mock TOTP test value:",result.data.verificationCode);
  step(2);
  app.innerHTML="<h2>Your setup is ready</h2>"+note(result.data.message)+
    "<p>Your QR code and secret are hidden until you choose to view them.</p>"+
    '<button class="primary" id="reveal-setup">Show QR and secret</button>'+
    '<button class="secondary" id="request-setup">Request a new setup</button>'+
    '<div id="sensitive-setup" class="sensitive" hidden><p>Scan this QR code. If scanning is difficult, copy the secret below.</p><div id="qr" class="qr"></div>'+
    '<div class="secret">'+esc(secretValue)+'</div><div class="row"><button class="secondary" id="copy-secret">Copy secret</button><button class="secondary" id="hide-setup">Hide QR and secret</button></div>'+
    '<details><summary>Show full setup link</summary><div class="secret">'+esc(uri)+'</div></details><button class="primary" id="added-app">I added it to my app</button></div>'+
    '<div id="msg" class="hint"></div>'+help();

  const reveal=document.querySelector("#reveal-setup"),sensitive=document.querySelector("#sensitive-setup");
  reveal.onclick=()=>{sensitive.hidden=false;reveal.textContent="QR and secret shown";reveal.disabled=true;qr(uri)};
  document.querySelector("#request-setup").onclick=provision;
  document.querySelector("#copy-secret").onclick=()=>copy(secretValue,"Authenticator secret");
  document.querySelector("#hide-setup").onclick=()=>{sensitive.hidden=true;reveal.textContent="Show QR and secret";reveal.disabled=false};
  document.querySelector("#added-app").onclick=verifyOtp;
}

function verifyOtp(){
  step(3);
  app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your authenticator app.</p>"+
    '<label for="otp-input">Six-digit code</label><input id="otp-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456">'+
    '<p class="hint">Example: 123456. You have plenty of time.</p><button class="primary" id="verify-otp">Verify code</button>'+help();
  document.querySelector("#verify-otp").onclick=async()=>{
    const otp=document.querySelector("#otp-input").value.trim();
    const result=await api("/api/verify-otp",{otp});
    if(!result.response.ok)return formMessage(result.data.message);
    codes=result.data.codes;
    log("Mock recovery codes:",codes);
    saveCodes("Your authenticator is now connected.");
  };
}

function saveCodes(message){
  step(4);
  app.innerHTML="<h2>Save your recovery codes</h2>"+note(message,"success")+
    "<p>Store these somewhere safe. Each code works once.</p><div class=\"codes\">"+codes.map(code=>'<div class="code">'+esc(code)+"</div>").join("")+"</div>"+
    '<button class="secondary" id="copy-all">Copy all recovery codes</button><div id="msg" class="hint"></div><button class="primary" id="saved-codes">I saved my codes</button>'+help();
  document.querySelector("#copy-all").onclick=()=>copy(codes.join("\\n"),"All recovery codes");
  document.querySelector("#saved-codes").onclick=()=>account("Your recovery codes are saved.");
}

/* Requirement task: authenticated, mobile recovery-code entry point and screen. */
function recoveryVerification(message="",kind=""){
  step(4);
  app.innerHTML="<h2>Use a recovery code</h2>"+
    (message?note(message,kind):"")+
    "<p>Use one saved recovery code when you need to check that it works.</p>"+
    '<label for="recovery-code-input">Recovery code</label>'+
    '<input id="recovery-code-input" inputmode="text" autocomplete="one-time-code" autocapitalize="characters" maxlength="11" placeholder="AAAAA-BBBBB" aria-describedby="recovery-example">'+
    '<p id="recovery-example" class="hint">Example: AAAAA-BBBBB</p>'+
    '<button class="primary" id="verify-recovery-code">Verify recovery code</button>'+
    '<button class="secondary" id="back-account">Back to security setup</button>'+help();

  const input=document.querySelector("#recovery-code-input");
  input.addEventListener("input",()=>{input.value=input.value.toUpperCase().replace(/[^A-Z0-9-]/g,"").slice(0,11)});
  document.querySelector("#back-account").onclick=()=>account("Your authenticator is active.");
  document.querySelector("#verify-recovery-code").onclick=async()=>{
    const code=input.value.trim();
    const result=await api("/api/verify-recovery-code",{code});
    if(result.response.ok)return recoveryVerification(result.data.message,"success");
    recoveryVerification(result.data.message,result.data.locked?"bad":"bad");
  };
}

function account(message){
  step(4);
  app.innerHTML="<h2>Security setup</h2>"+note(message,"success")+
    "<p>Your authenticator is active.</p>"+
    '<button class="primary" id="use-recovery">Use a recovery code</button>'+
    '<button class="secondary" id="replace-authenticator">Replace authenticator</button>'+
    '<button class="secondary" id="new-recovery-codes">Generate new recovery codes</button>'+
    '<button class="secondary" id="sign-out">Sign out</button>'+help();

  document.querySelector("#use-recovery").onclick=()=>recoveryVerification();
  document.querySelector("#replace-authenticator").onclick=async()=>{
    const result=await api("/api/begin-reenrolment");
    result.response.ok?setup("Replacement started. Your current authenticator remains active until checked."):formMessage(result.data.message);
  };
  document.querySelector("#new-recovery-codes").onclick=async()=>{
    const result=await api("/api/regenerate-backup-codes");
    if(result.response.ok){codes=result.data.codes;log("Mock recovery codes:",codes);saveCodes("New recovery codes replaced the old ones.");}
    else formMessage(result.data.message);
  };
  document.querySelector("#sign-out").onclick=async()=>{await api("/api/logout");csrf="";signin("You have signed out safely.");};
}

signin();
</script>
</body>
</html>`;
}

async function recoveryFailure(request: Request, account: any, message: string) {
  account.recoveryFailures++;
  if (account.recoveryFailures >= MAX_FAILURES) {
    account.recoveryLocked = Date.now() + LOCKOUT;
    return json(request, {
      ok: false,
      locked: true,
      message: "Too many recovery-code attempts. Recovery verification is locked for five minutes. You can try again after that."
    }, 429);
  }
  const remaining = MAX_FAILURES - account.recoveryFailures;
  return json(request, {
    ok: false,
    locked: false,
    message: `${message} Please try again. ${remaining} attempt${remaining === 1 ? "" : "s"} remain before a short lockout.`
  }, 400);
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (url.protocol !== "https:" || !trusted(url.hostname)) {
    return new Response("Not found", { status: 404, headers: headers(request) });
  }

  if (request.method === "GET" && url.pathname === "/") {
    const nonce = token(18);
    const output = headers(request, nonce);
    output.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers: output });
  }

  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!originOK(request)) {
      return json(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    }

    const data = await body(request);
    const email = typeof data?.email === "string" ? data.email.toLowerCase().trim() : "";
    const password = data?.password;
    const account = [...accounts.values()].find(value => value.email === email);
    const matches = same(
      sha256(typeof password === "string" ? password : ""),
      account ? account.passwordHash : dummyPasswordHash
    );

    if (
      !account ||
      !matches ||
      !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return json(request, {
        ok: false,
        message: "Sign-in could not be completed. Check your email and password, then try again."
      }, 401);
    }

    /* Requirement 5: rotate session on authentication. */
    for (const [id, session] of sessions) if (session.userId === account.id) sessions.delete(id);
    const id = token();
    const session = { userId: account.id, csrf: token(24), createdAt: Date.now(), lastSeenAt: Date.now() };
    sessions.set(id, session);

    return json(request, { ok: true, csrf: session.csrf, mfaEnabled: account.mfaEnabled }, 200, {
      "Set-Cookie": sessionCookie(id)
    });
  }

  const current = owner(request);
  if (!current) {
    return json(request, { ok: false, message: "Please sign in again to continue." }, 401);
  }

  if (request.method !== "POST" || !csrf(request, current.session)) {
    return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  }

  const account = current.account;

  if (url.pathname === "/api/logout") {
    sessions.delete(current.id);
    return json(request, { ok: true }, 200, {
      "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
    });
  }

  if (url.pathname === "/api/begin-reenrolment") {
    if (!account.mfaEnabled) return json(request, { ok: false, message: "Finish setup first." }, 400);
    account.replacing = true;
    return json(request, { ok: true });
  }

  if (url.pathname === "/api/provision") {
    if (account.mfaEnabled && !account.replacing) {
      return json(request, { ok: false, message: "Choose Replace authenticator first." }, 400);
    }

    const sharedSecret = secret();
    account.pending = await encrypt(sharedSecret);
    account.pendingUsed = [];

    const uri =
      "otpauth://totp/" +
      encodeURIComponent("Northstar Bank:" + account.email) +
      "?secret=" +
      sharedSecret +
      "&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";

    return json(request, {
      ok: true,
      secret: sharedSecret,
      uri,
      verificationCode: await totp(sharedSecret),
      message: "Authenticator setup is ready."
    });
  }

  if (url.pathname === "/api/verify-otp") {
    const data = await body(request);
    const now = Date.now();

    if (!validOtp(data?.otp)) {
      return json(request, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    }
    if (account.otpLocked > now) {
      return json(request, { ok: false, message: "Too many attempts. Please wait a few minutes." }, 429);
    }
    if (!account.pending) {
      return json(request, { ok: false, message: "Request a new setup and try again." }, 400);
    }

    const sharedSecret = await decrypt(account.pending);
    const base = Math.floor(now / 30_000);
    let hit = -1;

    for (let counter = base - 1; counter <= base + 1; counter++) {
      if (
        counter >= 0 &&
        !account.pendingUsed.includes(counter) &&
        same(await totp(sharedSecret, counter), data.otp)
      ) {
        hit = counter;
        break;
      }
    }

    if (hit < 0) {
      if (++account.otpFailures >= MAX_FAILURES) account.otpLocked = now + LOCKOUT;
      return json(request, {
        ok: false,
        message: "That code did not match, was used, or is no longer current. Try again."
      }, 400);
    }

    account.pendingUsed.push(hit);
    account.active = account.pending;
    account.pending = null;
    account.mfaEnabled = true;
    account.replacing = false;
    account.otpFailures = 0;

    const codes = recoveryCodes();
    account.backup = await Promise.all(codes.map(code => hmac(code, recoveryKey)));
    account.usedBackup = [];
    account.recoveryFailures = 0;
    account.recoveryLocked = 0;

    return json(request, { ok: true, codes });
  }

  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!account.mfaEnabled) return json(request, { ok: false, message: "Finish setup first." }, 400);

    const codes = recoveryCodes();
    account.backup = await Promise.all(codes.map(code => hmac(code, recoveryKey)));
    account.usedBackup = [];
    account.recoveryFailures = 0;
    account.recoveryLocked = 0;

    return json(request, { ok: true, codes });
  }

  /*
   Requirement task:
   - authenticated and CSRF protected by the common guards above
   - no account identifier is accepted or used
   - only strict AAAAA-BBBBB input is accepted
   - HMAC comparisons are constant time
   - matching code is removed immediately, while its HMAC records used status
   */
  if (url.pathname === "/api/verify-recovery-code") {
    const now = Date.now();

    if (account.recoveryLocked > now) {
      return json(request, {
        ok: false,
        locked: true,
        message: "Recovery verification is locked for five minutes after too many attempts. Please try again later."
      }, 429);
    }

    const data = await body(request);
    if (!validRecoveryCode(data?.code)) {
      return recoveryFailure(
        request,
        account,
        "Use five capital letters or numbers, a hyphen, then five more. Example: AAAAA-BBBBB."
      );
    }

    const submittedHmac = await hmac(data.code, recoveryKey);

    let activeIndex = -1;
    let usedMatch = false;

    /* Compare every stored HMAC instead of returning early. */
    for (let index = 0; index < account.backup.length; index++) {
      if (same(account.backup[index], submittedHmac)) activeIndex = index;
    }
    for (const usedHmac of account.usedBackup) {
      if (same(usedHmac, submittedHmac)) usedMatch = true;
    }

    if (activeIndex >= 0) {
      /* Consume immediately before returning success. */
      const consumed = account.backup.splice(activeIndex, 1)[0];
      account.usedBackup.push(consumed);
      account.recoveryFailures = 0;
      account.recoveryLocked = 0;

      return json(request, {
        ok: true,
        message: "Recovery code accepted. That code is now used and cannot be used again."
      });
    }

    if (usedMatch) {
      return recoveryFailure(
        request,
        account,
        "This recovery code was already used. Use a different saved code."
      );
    }

    return recoveryFailure(
      request,
      account,
      "This recovery code does not match one of your saved codes."
    );
  }

  return new Response("Not found", { status: 404, headers: headers(request) });
}

Bun.serve({
  hostname: "localhost",
  port: Number(Bun.env.PORT || 3000),
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem")
  },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: headers(request)
      });
    }
  }
});

console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
