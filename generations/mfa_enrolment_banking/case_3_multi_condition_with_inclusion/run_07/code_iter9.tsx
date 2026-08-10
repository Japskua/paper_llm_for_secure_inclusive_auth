
/**
 * MFA Enrolment System — single-file Bun HTTPS server and mobile web SPA.
 * Run: bun app.ts
 * Security §§1–5: owner-bound sessions, CSRF, TLS cookies, headers, validation,
 * encrypted TOTP seed, hashed recovery codes, expiry and failed-attempt lockout.
 */
const enc = new TextEncoder(), dec = new TextDecoder();
const TRUSTED = "https://localhost:3000";
const ACADEMIC = Bun.env.MFA_REAL_PRODUCTION !== "true";
const IDLE = 20 * 60e3, ABS = 8 * 60 * 60e3, LOCK = 15 * 60e3, LIFE = 10 * 60e3, MAX = 5;
const TEST_SECRET = "JBSWY3DPEHPK3PXPX", TEST_ID = "123456";
const TEST_CODES = [
  "DEMO0001-CODE0001", "DEMO0002-CODE0002", "DEMO0003-CODE0003", "DEMO0004-CODE0004",
  "DEMO0005-CODE0005", "DEMO0006-CODE0006", "DEMO0007-CODE0007", "DEMO0008-CODE0008"
];

const key = await crypto.subtle.importKey(
  "raw",
  crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"]
);

type Stage = "identity" | "setup" | "confirm" | "recovery" | "complete";
type Session = { id: string; csrf: string; stage: Stage; created: number; seen: number };
type Guard = { failures: number; locked: number };
type Code = Guard & { hash: string; expires: number; used: boolean; next: number };

const sessions = new Map<string, Session>();
const account = {
  email: "marcus@example.com",
  password: "BankPass!42",
  identity: null as Code | null,
  secret: "",
  backups: [] as string[],
  enabled: false,
  totp: { failures: 0, locked: 0, used: new Set<number>() },
  recovery: { failures: 0, locked: 0 },
  signin: { failures: 0, locked: 0 }
};

const now = () => Date.now();
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const token = (n = 32) => Buffer.from(random(n)).toString("base64url");
const sha = async (s: string) =>
  Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(s))).toString("base64url");

/* Security §3: uses crypto.getRandomValues, never Math.random. */
const sixDigitCode = () => {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(values[0] % 1_000_000).padStart(6, "0");
};

const encrypt = async (s: string) => {
  const iv = random(12);
  const c = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(s));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(c).toString("base64url");
};
const decrypt = async (s: string) => {
  const [iv, c] = s.split(".");
  return dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    key,
    Buffer.from(c, "base64url")
  ));
};

function b32(a: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "", bits = 0, value = 0;
  for (const byte of a) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) out += alphabet[(value >>> (bits -= 5)) & 31];
  }
  return out + (bits ? alphabet[(value << (5 - bits)) & 31] : "");
}
function unb32(s: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/[=\s]/g, "").toUpperCase()) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw Error("Invalid secret");
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) out.push((value >>> (bits -= 8)) & 255);
  }
  return new Uint8Array(out);
}
async function totp(secret: string, counter: number) {
  const k = await crypto.subtle.importKey(
    "raw",
    unb32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const data = new Uint8Array(8);
  let x = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    data[i] = Number(x & 255n);
    x >>= 8n;
  }
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
  const p = h[19] & 15;
  const value = ((h[p] & 127) << 24) | (h[p + 1] << 16) | (h[p + 2] << 8) | h[p + 3];
  return String(value % 1e6).padStart(6, "0");
}

function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const part of (r.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const headers = {
  "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer"
};

function out(data: any, status = 200, setCookies: string[] = []) {
  const h = new Headers({ ...headers, "Content-Type": "application/json; charset=utf-8" });
  setCookies.forEach(cookie => h.append("Set-Cookie", cookie));
  return new Response(JSON.stringify(data), { status, headers: h });
}

function session(r: Request) {
  const s = sessions.get(cookies(r).mfa_session || "");
  const t = now();
  if (!s || t - s.seen > IDLE || t - s.created > ABS) return null;
  s.seen = t;
  return s;
}

/* Security §1: every modifying MFA endpoint requires owner session, Origin and CSRF. */
function protect(r: Request) {
  const s = session(r);
  if (!s) return [null, out({ ok: false, message: "Please sign in again to continue." }, 401)] as const;
  if (r.headers.get("origin") !== null && r.headers.get("origin") !== TRUSTED) {
    return [null, out({ ok: false, message: "This request is not allowed." }, 403)] as const;
  }
  if (r.headers.get("x-csrf-token") !== s.csrf) {
    return [null, out({ ok: false, message: "Please try that step again." }, 403)] as const;
  }
  return [s, null] as const;
}

async function body(r: Request) {
  try { return await r.json(); } catch { return null; }
}
const otp = (x: any) => typeof x === "string" && /^\d{6}$/.test(x);
const validEmail = (x: any) => typeof x === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x) && x.length <= 254;
const validPassword = (x: any) => typeof x === "string" && x.length > 0 && x.length <= 256;
const stage = (s: Session, allowed: Stage[]) => allowed.includes(s.stage);

function lockMessage() {
  return "Too many attempts were made. Please wait 15 minutes, then try again.";
}

async function api(r: Request, p: string): Promise<Response> {
  if (p === "/api/signin" && r.method === "POST") {
    const b = await body(r);
    const csrfCookie = cookies(r).mfa_csrf;
    const guard = account.signin;

    if (guard.locked > now()) {
      return out({ ok: false, message: "Sign-in is temporarily unavailable. Please wait 15 minutes, then try again." }, 429);
    }

    const validCsrf = !!csrfCookie && csrfCookie === r.headers.get("x-csrf-token");
    const authenticated = validCsrf && validEmail(b?.email) && validPassword(b?.password) &&
      b.email === account.email && b.password === account.password;

    if (!authenticated) {
      guard.failures++;
      if (guard.failures >= MAX) {
        guard.locked = now() + LOCK;
        guard.failures = 0;
      }
      /* Security §5: same generic response for all sign-in failures. */
      return out({ ok: false, message: "Check your email and password, then try again." }, 401);
    }

    guard.failures = 0;
    guard.locked = 0;
    const id = token(), csrf = token(24);
    const s: Session = {
      id,
      csrf,
      stage: (account.enabled ? "complete" : "identity") as Stage,
      created: now(),
      seen: now()
    };
    sessions.set(id, s);
    return out(
      { ok: true, csrf, stage: s.stage, academicMode: ACADEMIC, message: "Signed in." },
      200,
      [
        `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
        `mfa_csrf=${csrf}; Path=/; Secure; SameSite=Strict; Max-Age=28800`
      ]
    );
  }

  /* Bootstrap endpoint restores any valid authenticated enrolment stage. */
  if (p === "/api/me" && r.method === "GET") {
    const s = session(r);
    return s
      ? out({ ok: true, csrf: s.csrf, stage: s.stage, academicMode: ACADEMIC })
      : out({ ok: false }, 401);
  }

  const [s, fail] = protect(r);
  if (fail) return fail;

  if (p === "/api/identity/send" && r.method === "POST" && stage(s!, ["identity"])) {
    const code = ACADEMIC ? TEST_ID : sixDigitCode();
    account.identity = {
      hash: await sha(code),
      expires: now() + LIFE,
      used: false,
      failures: 0,
      locked: 0,
      next: now() + 60e3
    };
    return out({
      ok: true,
      simulationCode: ACADEMIC ? code : undefined,
      message: "A code was sent. Take your time entering it."
    });
  }

  if (p === "/api/identity/verify" && r.method === "POST" && stage(s!, ["identity"])) {
    const b = await body(r);
    const x = account.identity;

    if (x && x.locked > now()) return out({ ok: false, message: lockMessage() }, 429);

    const matches = !!x && otp(b?.code) && !x.used && x.expires >= now() && (await sha(b.code)) === x.hash;
    if (!matches) {
      if (x) {
        x.failures++;
        if (x.failures >= MAX) {
          x.locked = now() + LOCK;
          x.failures = 0;
          return out({ ok: false, message: lockMessage() }, 429);
        }
      }
      return out({
        ok: false,
        message: "That code did not match. Check all 6 digits or request another code."
      }, 400);
    }

    x.used = true;
    x.failures = 0;
    x.locked = 0;
    s!.stage = "setup";
    return out({ ok: true, message: "Identity checked. Next, set up your authenticator." });
  }

  if (p === "/api/authenticator/setup" && r.method === "POST" && stage(s!, ["setup"])) {
    if (!account.secret) account.secret = await encrypt(ACADEMIC ? TEST_SECRET : b32(random(20)));
    const secret = await decrypt(account.secret);
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return out({ ok: true, secret, uri });
  }

  if (p === "/api/authenticator/confirm" && r.method === "POST" && stage(s!, ["setup", "confirm"])) {
    if (!account.secret) return out({ ok: false, message: "Create a setup key first." }, 400);
    s!.stage = "confirm";
    const code = ACADEMIC ? await totp(await decrypt(account.secret), Math.floor(now() / 30000)) : undefined;
    return out({
      ok: true,
      simulationCode: code,
      message: "Now enter the current code from your authenticator."
    });
  }

  if (p === "/api/authenticator/refresh" && r.method === "POST" && stage(s!, ["confirm"])) {
    const code = ACADEMIC ? await totp(await decrypt(account.secret), Math.floor(now() / 30000)) : undefined;
    return out({
      ok: true,
      simulationCode: code,
      message: "A new current test code is ready. Retrying is safe and does not count against you."
    });
  }

  if (p === "/api/authenticator/verify" && r.method === "POST" && stage(s!, ["confirm"])) {
    const b = await body(r), state = account.totp;
    if (state.locked > now()) return out({ ok: false, message: "Too many tries. Please wait, then try a new code." }, 429);

    let good = false;
    const center = Math.floor(now() / 30000);
    const secret = await decrypt(account.secret);
    if (otp(b?.code)) {
      for (const n of [center - 1, center, center + 1]) {
        if (b.code === await totp(secret, n) && !state.used.has(n)) {
          good = true;
          state.used.add(n);
        }
      }
    }

    if (!good) {
      if (++state.failures >= MAX) state.locked = now() + LOCK;
      return out({
        ok: false,
        message: "That code did not match or was already used. Get a new current code and try again."
      }, 400);
    }

    state.failures = 0;
    state.locked = 0;
    s!.stage = "recovery";
    return out({ ok: true, message: "Authenticator confirmed. Next, save your recovery codes." });
  }

  if (p === "/api/recovery/create" && r.method === "POST" && stage(s!, ["recovery"])) {
    const codes = ACADEMIC ? [...TEST_CODES] : Array.from({ length: 8 }, () => token(8).toUpperCase());
    account.backups = await Promise.all(codes.map(sha));
    return out({ ok: true, codes, message: "Your recovery codes are ready. Save them somewhere private." });
  }

  if (p === "/api/recovery/finish" && r.method === "POST" && stage(s!, ["recovery"]) && account.backups.length === 8) {
    account.enabled = true;
    s!.stage = "complete";
    return out({ ok: true, message: "MFA is now on." });
  }

  if (p === "/api/logout" && r.method === "POST") {
    sessions.delete(s!.id);
    return out({ ok: true }, 200, [
      "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
      "mfa_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0"
    ]);
  }

  return out({ ok: false, message: "We could not complete that step. Please try again." }, 404);
}

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank MFA</title>
<style>
:root{color-scheme:light}
body{margin:0;background:#eef4f8;color:#14283d;font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}
.shell{max-width:580px;min-height:100vh;margin:auto;padding:22px;box-sizing:border-box;background:#fff}
h1{font-size:1.6rem;line-height:1.3;margin:18px 0 10px}
h2{font-size:1.2rem}.brand{font-weight:bold;color:#064a98}.step,.small{color:#526779;font-size:.9rem}
.card,.hint{border:1px solid #c9d6e1;border-radius:10px;padding:16px;margin:16px 0}
.hint{border-left:5px solid #075bc7;background:#f5faff}
label{display:block;font-weight:bold;margin:14px 0 5px}
input,button{font:inherit;letter-spacing:inherit;box-sizing:border-box}
input{width:100%;padding:13px;border:2px solid #8499ac;border-radius:8px;background:#fff}
input:focus,button:focus{outline:3px solid #f2b84b;outline-offset:2px}
.code{text-align:center;font-size:1.4rem;font-weight:bold;letter-spacing:.2em}
.primary,.secondary{width:100%;margin-top:16px;padding:14px;border-radius:8px;font-weight:bold;cursor:pointer}
.primary{background:#075bc7;color:#fff;border:0}.secondary{color:#064d9e;background:#fff;border:2px solid #075bc7}
.message{padding:12px;border-radius:8px;background:#e5f6ed;margin:14px 0}.error{background:#fff0ef;color:#8c2019}
.secret{font-family:monospace;white-space:pre-wrap;word-break:break-all;background:#f4f7f9;padding:12px;border-radius:7px;letter-spacing:.08em}
.protected{filter:blur(7px);user-select:none}.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.actions button{margin-top:10px}
.logs{margin-top:30px;border-top:2px solid #c9d6e1}.logs pre{white-space:pre-wrap;background:#0e2436;color:#dff5ff;padding:12px;border-radius:8px;font:12px/1.5 monospace}
[hidden]{display:none!important}
</style>
</head>
<body>
<main class="shell">
<header>
<div class="brand">🏦 Local Bank</div>
<div id="step" class="step">Secure account setup</div>
</header>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Simulation logs">
<h2>🧾 Logs</h2>
<p class="small">Simulation messages appear here and in the browser console.</p>
<pre id="logs">Ready.</pre>
</section>
</main>
<script>
(()=>{
"use strict";
let csrf="", mode=false;
const app=document.querySelector("#app"), logs=document.querySelector("#logs"), step=document.querySelector("#step");

const E=(tag,attrs={},text="")=>{
  const el=document.createElement(tag);
  Object.entries(attrs).forEach(([key,value])=>{
    if(key.startsWith("on")) el.addEventListener(key.slice(2),value);
    else el.setAttribute(key,value);
  });
  el.textContent=text;
  return el;
};
const log=(text)=>{console.log(text);logs.textContent+="\n"+text;};
const message=(text,isError=false)=>E("div",{class:"message "+(isError?"error":""),role:isError?"alert":"status"},text);
const hint=()=>E("p",{class:"hint"},"💡 Need help? Take your time. Retrying is safe and does not penalize you.");
const cookie=(name)=>{
  const item=document.cookie.split("; ").find(item=>item.startsWith(name+"="));
  return item?decodeURIComponent(item.split("=").slice(1).join("=")):"";
};
const showError=(container,text)=>{
  const old=container.querySelector(".message.error");
  if(old) old.remove();
  container.prepend(message(text,true));
};
const otpInput=()=>{
  const input=E("input",{
    class:"code",type:"text",placeholder:"123456",autocomplete:"one-time-code",
    inputmode:"numeric",maxlength:"6",pattern:"[0-9]{6}","aria-label":"Six digit code"
  });
  input.addEventListener("input",()=>{input.value=input.value.replace(/\D/g,"").slice(0,6);});
  return input;
};
async function api(path,method="GET",data){
  try{
    const response=await fetch(path,{
      method,
      credentials:"same-origin",
      headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},
      body:data===undefined?undefined:JSON.stringify(data)
    });
    const json=await response.json();
    if(!response.ok&&!json.message) json.message="We could not complete that step. Please try again.";
    return json;
  }catch{
    return {ok:false,message:"We could not reach the secure service. Please try again."};
  }
}
/* Clipboard controls avoid manual transcription of sensitive values. */
async function copyText(text,feedback){
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{
      const area=document.createElement("textarea");
      area.value=text; area.setAttribute("readonly","");
      area.style.position="fixed"; area.style.opacity="0";
      document.body.append(area); area.select();
      const copied=document.execCommand("copy");
      area.remove();
      if(!copied) throw Error("Copy unavailable");
    }
    feedback.textContent="Copied. You can paste it where you need it.";
    feedback.className="message";
  }catch{
    feedback.textContent="We could not copy that. Select the value and copy it yourself.";
    feedback.className="message error";
  }
}
function sensitiveControls(value,label){
  const box=E("div");
  const valueBox=E("div",{class:"secret protected","aria-label":label+" hidden"},value);
  const feedback=E("div",{class:"message",hidden:"hidden"},"");
  const reveal=E("button",{class:"secondary",type:"button","aria-pressed":"false"},"Reveal "+label);
  const copy=E("button",{class:"secondary",type:"button"},"Copy "+label);
  reveal.onclick=()=>{
    const hidden=valueBox.classList.toggle("protected");
    valueBox.setAttribute("aria-label",label+(hidden?" hidden":" shown"));
    reveal.textContent=(hidden?"Reveal ":"Hide ")+label;
    reveal.setAttribute("aria-pressed",String(!hidden));
  };
  copy.onclick=async()=>{
    feedback.hidden=false;
    await copyText(value,feedback);
  };
  const actions=E("div",{class:"actions"});
  actions.append(reveal,copy);
  box.append(valueBox,actions,feedback);
  return box;
}
function academicCode(kind,code){
  if(mode&&code){
    const line="ACADEMIC SIMULATION "+kind+": "+code;
    console.log(line);
    /* Visible panel confirms simulated delivery without exposing hidden values casually. */
    log("Academic simulation "+kind+" delivered to browser console.");
  }
}
function completion(){
  step.textContent="Step complete";
  app.replaceChildren(
    E("h1",{},"MFA is ready"),
    message("MFA is now on."),
    E("p",{},"✅ Your authenticator and recovery codes are set up.")
  );
}
function signin(){
  step.textContent="Sign in";
  app.replaceChildren(E("h1",{},"Sign in to start MFA setup"));
  const form=E("form");
  const email=E("input",{
    type:"email",placeholder:"marcus@example.com",autocomplete:"username",
    inputmode:"email",required:"required","aria-describedby":"email-example"
  });
  const password=E("input",{
    type:"password",placeholder:"BankPass!42",autocomplete:"current-password",required:"required"
  });
  form.append(
    E("label",{for:"email"},"Email"),email,
    E("p",{id:"email-example",class:"small"},"Example: marcus@example.com"),
    E("label",{for:"password"},"Password"),password,
    E("button",{class:"primary",type:"submit"},"Sign in")
  );
  form.onsubmit=async(event)=>{
    event.preventDefault();
    const d=await api("/api/signin","POST",{email:email.value,password:password.value});
    if(!d.ok){showError(form,d.message);return;}
    csrf=d.csrf; mode=!!d.academicMode;
    route(d.stage);
  };
  app.append(form,hint());
}
function identity(){
  step.textContent="Step 1 of 4 · Verify identity";
  app.replaceChildren(E("h1",{},"Verify it is you"),E("p",{},"📩 Send one short code."));
  const send=E("button",{class:"primary",type:"button"},"Send identity code");
  send.onclick=async()=>{
    const d=await api("/api/identity/send","POST",{});
    if(!d.ok){showError(app,d.message);return;}
    academicCode("identity code",d.simulationCode);
    send.disabled=true;
    const form=E("form");
    const input=otpInput();
    form.append(
      E("label",{for:"identity-code"},"6-digit code"),
      input,
      E("p",{class:"small"},"Example: 123456"),
      E("button",{class:"primary",type:"submit"},"Check code")
    );
    form.onsubmit=async(event)=>{
      event.preventDefault();
      const x=await api("/api/identity/verify","POST",{code:input.value});
      if(!x.ok){showError(form,x.message);return;}
      setup();
    };
    app.append(message(d.message),form);
    input.focus();
  };
  app.append(send,hint());
}
async function setup(){
  step.textContent="Step 2 of 4 · Authenticator";
  app.replaceChildren(E("h1",{},"Set up your authenticator"),E("p",{},"📱 Copy this setup key into your authenticator app."));
  const d=await api("/api/authenticator/setup","POST",{});
  if(!d.ok){app.append(message(d.message,true),hint());return;}
  app.append(
    E("p",{class:"small"},"Use your authenticator app's manual setup option. You do not need to type this key."),
    sensitiveControls(d.secret,"setup key")
  );
  const next=E("button",{class:"primary",type:"button"},"I added it to my app");
  next.onclick=async()=>{
    const x=await api("/api/authenticator/confirm","POST",{});
    if(!x.ok){showError(app,x.message);return;}
    academicCode("authenticator test code",x.simulationCode);
    confirm();
  };
  app.append(next,hint());
}
function confirm(){
  step.textContent="Step 3 of 4 · Check authenticator";
  app.replaceChildren(
    E("h1",{},"Check your authenticator"),
    E("p",{},"🔢 Enter the current 6-digit code. Take as long as you need.")
  );
  const form=E("form"), input=otpInput();
  const refresh=E("button",{class:"secondary",type:"button"},"Get a new test code");
  refresh.onclick=async()=>{
    const d=await api("/api/authenticator/refresh","POST",{});
    if(!d.ok){showError(form,d.message);return;}
    academicCode("refreshed authenticator code",d.simulationCode);
    showError(form,"");
    const old=form.querySelector(".message.error"); if(old) old.remove();
    app.append(message(d.message));
  };
  form.append(
    E("label",{for:"auth-code"},"6-digit code"),
    input,
    E("p",{class:"small"},"Example: 123456"),
    E("button",{class:"primary",type:"submit"},"Confirm authenticator")
  );
  form.onsubmit=async(event)=>{
    event.preventDefault();
    const d=await api("/api/authenticator/verify","POST",{code:input.value});
    if(!d.ok){showError(form,d.message);return;}
    recovery();
  };
  app.append(form,refresh,hint());
  input.focus();
}
async function recovery(){
  step.textContent="Step 4 of 4 · Recovery codes";
  app.replaceChildren(E("h1",{},"Save recovery codes"),E("p",{},"🗝️ Keep these somewhere private."));
  const d=await api("/api/recovery/create","POST",{});
  if(!d.ok){app.append(message(d.message,true),hint());return;}
  if(mode&&Array.isArray(d.codes)){
    console.log("ACADEMIC SIMULATION recovery codes:",d.codes);
    log("Academic simulation recovery codes delivered to browser console.");
  }
  app.append(
    E("p",{class:"small"},"They are hidden until you choose Reveal. Copying saves you from typing them."),
    sensitiveControls(d.codes.join("\n"),"recovery codes")
  );
  const finish=E("button",{class:"primary",type:"button"},"I saved my codes");
  finish.onclick=async()=>{
    const x=await api("/api/recovery/finish","POST",{});
    if(!x.ok){showError(app,x.message);return;}
    /* Completion is rendered only after the server confirms ok:true. */
    completion();
  };
  app.append(finish,hint());
}
function route(currentStage){
  if(currentStage==="identity") identity();
  else if(currentStage==="setup") setup();
  else if(currentStage==="confirm") confirm();
  else if(currentStage==="recovery") recovery();
  else if(currentStage==="complete") completion();
  else signin();
}
(async()=>{
  csrf=cookie("mfa_csrf");
  if(!csrf){
    csrf=Array.from(crypto.getRandomValues(new Uint8Array(24)),x=>x.toString(16).padStart(2,"0")).join("");
    document.cookie="mfa_csrf="+csrf+"; Path=/; Secure; SameSite=Strict";
  }
  const d=await api("/api/me");
  if(d.ok){
    csrf=d.csrf;
    mode=!!d.academicMode;
    route(d.stage);
  }else signin();
})();
})();
</script>
</body>
</html>`;

Bun.serve({
  hostname: "localhost",
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem")
  },
  fetch: async (r) => {
    try {
      const u = new URL(r.url);
      if (u.pathname === "/" && r.method === "GET") {
        return new Response(HTML, { headers: { ...headers, "Content-Type": "text/html; charset=utf-8" } });
      }
      if (u.pathname.startsWith("/api/")) return api(r, u.pathname);
      return out({ ok: false, message: "Not found." }, 404);
    } catch {
      return out({ ok: false, message: "We could not complete that step." }, 500);
    }
  }
});
