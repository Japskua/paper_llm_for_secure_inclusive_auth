
import { existsSync, readFileSync } from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from "node:crypto";

/*
  MFA Security Evaluation §§1–5:
  This is a deliberately small, in-memory demonstration service. Secrets are
  encrypted or hashed server-side and mock values are returned only for the
  requested academic demonstration flow.
*/

const PORT = Number(process.env.PORT || 3000);
const SESSION_COOKIE = "mfa_session";
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const RECOVERY_EXPIRY_MS = 365 * 24 * 60 * 60 * 1000;
const encryptionKey = randomBytes(32);
const pepper = randomBytes(32);
const sessions = new Map<string, Session>();

type ProtectedValue = {
  iv: Buffer;
  tag: Buffer;
  data: Buffer;
};

type BackupCode = {
  salt: Buffer;
  hash: Buffer;
  used: boolean;
  expiresAt: number;
};

type Session = {
  id: string;
  phase: "preauth" | "auth";
  userId?: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  email?: string;
  identityCode?: string;
  identityExpires?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockedUntil?: number;
  mfaEnabled: boolean;
  enrollment?: {
    secret: ProtectedValue;
    otpHash: Buffer;
    consumed: boolean;
    failures: number;
    lockedUntil?: number;
  };
  backupCodes: BackupCode[];
  recoveryFailures: number;
  recoveryLockedUntil?: number;
};

function opaqueToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function encrypt(value: string): ProtectedValue {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), data };
}

function decrypt(value: ProtectedValue): string {
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, value.iv);
  decipher.setAuthTag(value.tag);
  return Buffer.concat([decipher.update(value.data), decipher.final()]).toString("utf8");
}

function protectedHash(value: string, salt = randomBytes(16)) {
  return {
    salt,
    hash: pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256"),
  };
}

function hashesMatch(value: string, salt: Buffer, expected: Buffer) {
  const actual = pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  const value = request.headers.get("cookie") || "";
  for (const entry of value.split(";")) {
    const index = entry.indexOf("=");
    if (index > 0) result[entry.slice(0, index).trim()] = entry.slice(index + 1).trim();
  }
  return result;
}

function createSession(phase: "preauth" | "auth" = "preauth", userId?: string): Session {
  const now = Date.now();
  const session: Session = {
    id: opaqueToken(),
    phase,
    userId,
    csrf: opaqueToken(),
    createdAt: now,
    lastSeen: now,
    identityFailures: 0,
    mfaEnabled: false,
    backupCodes: [],
    recoveryFailures: 0,
  };
  sessions.set(session.id, session);
  return session;
}

function validSession(request: Request) {
  const id = parseCookies(request)[SESSION_COOKIE];
  const session = id ? sessions.get(id) : undefined;
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}

function sessionCookie(session: Session) {
  return `${SESSION_COOKIE}=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(
    SESSION_ABSOLUTE_MS / 1000,
  )}`;
}

function clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function trustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const url = new URL(origin);
    return (
      url.protocol === "https:" &&
      url.port === String(PORT) &&
      ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

function commonHeaders(request: Request, nonce?: string) {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  const origin = request.headers.get("origin");
  if (origin && trustedOrigin(request)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
  }
  return headers;
}

function json(request: Request, data: unknown, status = 200, cookie?: string) {
  const headers = commonHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(request: Request, status = 400, message = "We could not complete that step. Please try again.") {
  return json(request, { ok: false, message }, status);
}

async function body(request: Request): Promise<Record<string, unknown> | undefined> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return undefined;
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function csrf(request: Request, session: Session) {
  if (!trustedOrigin(request)) return false;
  const token = request.headers.get("x-csrf-token");
  return !!token && token.length === session.csrf.length && timingSafeEqual(Buffer.from(token), Buffer.from(session.csrf));
}

/* Security §1: every MFA operation first requires this server-side owner check. */
function authenticated(request: Request) {
  const session = validSession(request);
  if (!session || session.phase !== "auth" || session.userId !== "marcus-account") return undefined;
  return session;
}

function createIdentityCode() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let result = "";
  for (const byte of bytes) result += alphabet[byte % alphabet.length];
  return result;
}

function backupValue() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(12);
  let raw = "";
  for (const byte of bytes) raw += alphabet[byte % alphabet.length];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

function issueBackupCodes(session: Session) {
  const plain = Array.from({ length: 8 }, backupValue);
  session.backupCodes = plain.map((code) => {
    const hashed = protectedHash(code);
    return { ...hashed, used: false, expiresAt: Date.now() + RECOVERY_EXPIRY_MS };
  });
  return plain;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263c;--muted:#55657a;--blue:#075cc7;--blue2:#064b9f;--pale:#edf6ff;--line:#d5dfeb;--good:#107044;--warn:#a94d00;--bg:#f5f8fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}
main{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:22px 18px 32px}.brand{font-weight:700;font-size:1.05rem;color:#064b9f}.brand span{font-size:1.35rem;margin-right:7px}h1{font-size:1.58rem;line-height:1.3;letter-spacing:.02em;margin:20px 0 8px}h2{font-size:1.25rem;line-height:1.35;margin:15px 0 8px}p{margin:7px 0 16px;color:var(--muted)}.steps{display:flex;gap:5px;margin:18px 0 24px}.step{height:8px;border-radius:8px;background:#dbe3ed;flex:1}.step.on{background:var(--blue)}.card{border:1px solid var(--line);border-radius:14px;padding:16px;margin:16px 0;background:#fff}.hint{background:var(--pale);border-left:4px solid var(--blue);padding:12px 13px;border-radius:7px;color:#24445f;font-size:.92rem}.notice{padding:12px 13px;border-radius:8px;background:#eaf8f0;color:#105537;margin:14px 0}.error{padding:12px 13px;border-radius:8px;background:#fff0e8;color:#843900;margin:14px 0}.label{font-weight:700;display:block;margin:16px 0 5px}input{width:100%;font:inherit;letter-spacing:.08em;border:2px solid #9aaabd;border-radius:9px;padding:13px;color:var(--ink);background:#fff}input:focus{outline:3px solid #a9d0ff;border-color:var(--blue)}button{font:inherit;letter-spacing:.025em;border-radius:9px;border:0;padding:13px 16px;cursor:pointer;font-weight:700}button.primary{width:100%;background:var(--blue);color:#fff;margin-top:18px}button.primary:hover{background:var(--blue2)}button.secondary{background:#e8f0fa;color:#17436d;margin:8px 6px 0 0}button.link{padding:6px 0;background:transparent;color:var(--blue);text-decoration:underline;font-weight:600}.small{font-size:.88rem}.secret{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;letter-spacing:.08em;background:#f4f7fa;padding:12px;border-radius:8px;color:#22384d}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:ui-monospace,Consolas,monospace;font-size:1.04rem;letter-spacing:.12em;padding:8px 4px;border-bottom:1px solid var(--line)}.qr{width:184px;height:184px;display:grid;grid-template-columns:repeat(13,1fr);gap:2px;background:#fff;padding:7px;border:1px solid var(--line);margin:12px auto}.qr i{background:#fff}.qr i.dark{background:#17263c}.logs{margin-top:27px;border-top:2px solid var(--line);padding-top:13px}.logs h2{font-size:1rem}.logbox{background:#111d2b;color:#e7f2ff;border-radius:9px;padding:10px;min-height:66px;max-height:180px;overflow:auto;font-family:ui-monospace,monospace;font-size:.77rem;letter-spacing:0;white-space:pre-wrap}.row{display:flex;flex-wrap:wrap;gap:4px}.hide{display:none!important}@media(max-width:370px){main{padding:17px 14px}body{font-size:15px}h1{font-size:1.4rem}}
</style>
</head>
<body><main id="app" aria-live="polite">Loading setup…</main>
<script nonce="${nonce}">
(() => {
"use strict";
/* Accessibility requirements: short stable screens, generous spacing, no timers or motion. */
const app=document.getElementById("app");
const state={csrf:"",auth:false,mfa:false,view:"signin",email:"",secret:"",codes:[],notice:"",error:"",qr:false,logs:[]};
const allowedViews=new Set(["signin","identity","home","enrol","codes","recovery"]);
function el(tag, props={}, ...children){const node=document.createElement(tag);for(const [key,value] of Object.entries(props)){if(key==="class")node.className=value;else if(key==="text")node.textContent=value;else if(key.startsWith("on"))node.addEventListener(key.slice(2),value);else if(value!==false&&value!=null)node.setAttribute(key,String(value));}for(const child of children){node.append(child instanceof Node?child:document.createTextNode(String(child)));}return node;}
function log(message){console.log(message);state.logs.push(message);if(state.logs.length>18)state.logs.shift();}
async function api(path, method="GET", data){const opt={method,credentials:"same-origin",headers:{}};if(method!=="GET"){opt.headers["Content-Type"]="application/json";opt.headers["X-CSRF-Token"]=state.csrf;opt.body=JSON.stringify(data||{});}let response;try{response=await fetch(path,opt);}catch{return {ok:false,message:"Connection problem. Please try again."};}const result=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));if(response.status===401){state.auth=false;state.view="signin";}return result;}
function status(container){if(state.error)container.append(el("div",{class:"error",role:"alert",text:state.error}));if(state.notice)container.append(el("div",{class:"notice",text:state.notice}));}
function header(root, step){root.append(el("div",{class:"brand"},el("span",{text:"⚓"}),"Harbour Bank"));const steps=el("div",{class:"steps","aria-label":"Setup progress"});for(let i=1;i<=4;i++)steps.append(el("div",{class:"step "+(i<=step?"on":""),"aria-hidden":"true"}));root.append(steps);}
function help(root){root.append(el("button",{class:"link",type:"button",onClick:()=>{state.notice="Help: You can take as long as you need. Nothing on this page expires while you read it.";state.error="";render();},text:"? Need a little help"}));}
function primary(root,text,fn){root.append(el("button",{class:"primary",type:"button",onClick:fn,text}));}
function input(label,type,attrs={}){const wrap=el("div");const id="field-"+Math.random().toString(36).slice(2);wrap.append(el("label",{class:"label",for:id,text:label}));wrap.append(el("input",{id,type,...attrs}));return wrap;}
function renderLogs(root){const section=el("section",{class:"logs","aria-label":"Demo logs"});section.append(el("h2",{text:"Logs"}));section.append(el("p",{class:"small",text:"Demo delivery messages also appear in your browser console."}));section.append(el("div",{class:"logbox",text:state.logs.join("\\n")||"No demo messages yet."}));root.append(section);}
function render(){if(!allowedViews.has(state.view))state.view="signin";app.replaceChildren();const root=el("div");app.append(root);if(state.view==="signin")signIn(root);if(state.view==="identity")identity(root);if(state.view==="home")home(root);if(state.view==="enrol")enrol(root);if(state.view==="codes")codes(root);if(state.view==="recovery")recovery(root);renderLogs(root);}
function signIn(root){header(root,1);root.append(el("h1",{text:"Sign in to set up MFA"}),el("p",{text:"We will send one short identity code. This demo does not use a real email."}));status(root);const field=input("Email address","email",{autocomplete:"email",inputmode:"email",placeholder:"marcus@example.com"});field.querySelector("input").value=state.email;root.append(field,el("div",{class:"hint",text:"Example: marcus@example.com"}));primary(root,"Send identity code",async()=>{const email=field.querySelector("input").value.trim();if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||email.length>120){state.error="Enter an email in this format: name@example.com.";render();return;}const r=await api("/api/signin/request","POST",{email});if(!r.ok){state.error=r.message;render();return;}state.email=email;log("Mock identity code delivered: "+r.mockCode);state.notice="A six-digit code was sent. In this demo, it is in the browser console and Logs panel.";state.error="";state.view="identity";render();});help(root);}
function identity(root){header(root,1);root.append(el("h1",{text:"Check your identity"}),el("p",{text:"Enter the six-digit code we sent."}));status(root);const field=input("Identity code","text",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});root.append(field,el("div",{class:"hint",text:"Take your time. You can request another code if you need one."}));primary(root,"Check code",async()=>{const code=field.querySelector("input").value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(code)){state.error="Enter all 6 numbers, for example 123456.";render();return;}const r=await api("/api/signin/verify","POST",{code});if(!r.ok){state.error=r.message;render();return;}state.csrf=r.csrf;state.auth=true;state.mfa=r.mfa;state.error="";state.notice="Identity checked. Next, set up your authenticator.";state.view="home";render();});root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="signin";state.notice="You can request a new code.";state.error="";render();},text:"Request another code"}));help(root);}
function home(root){header(root,state.mfa?4:2);root.append(el("h1",{text:state.mfa?"MFA is set up":"Set up your authenticator"}),el("p",{text:state.mfa?"Your account has an extra sign-in check. Keep recovery codes somewhere safe.":"Use an authenticator app to get a short code when needed."}));status(root);if(!state.mfa){root.append(el("div",{class:"hint",text:"You can scan a QR pattern, or copy a shorter setup secret instead."}));primary(root,"Set up authenticator",async()=>{const r=await api("/api/mfa/enroll","POST",{});if(!r.ok){state.error=r.message;render();return;}state.secret=r.secret;state.error="";state.notice="Setup secret ready. Choose the method that feels easiest.";log("Mock authenticator setup secret: "+r.secret);log("Mock authenticator OTP for verification: "+r.mockOtp);state.view="enrol";render();});}else{root.append(el("div",{class:"notice",text:"Authenticator confirmed. Your next step is to save recovery codes."}));primary(root,"View recovery codes",async()=>{state.view="codes";state.notice="";render();});root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="recovery";state.notice="";render();},text:"Test a recovery code"}));}root.append(el("button",{class:"link",type:"button",onClick:logout,text:"Sign out"}));help(root);}
function qr(secret){const box=el("div",{class:"qr",role:"img","aria-label":"A mock QR setup pattern"});let seed=0;for(const c of secret)seed=(seed*31+c.charCodeAt(0))>>>0;for(let i=0;i<169;i++){seed=(seed*1664525+1013904223)>>>0;box.append(el("i",{class:(seed>>>29)%2?"dark":""}));}return box;}
function enrol(root){header(root,2);root.append(el("h1",{text:"Add the authenticator"}),el("p",{text:"In your authenticator app, add an account. Scan the pattern or use the copied secret."}));status(root);root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.qr=!state.qr;render();},text:state.qr?"Hide QR pattern":"Show QR pattern"}));if(state.qr)root.append(qr(state.secret));root.append(el("h2",{text:"Manual setup secret"}),el("div",{class:"secret",text:state.secret}));root.append(el("button",{class:"secondary",type:"button",onClick:()=>copyText(state.secret,"The setup secret was copied."),text:"Copy setup secret"}),el("div",{class:"hint",text:"For this demo, the test authenticator code is in Logs. It does not expire while you read."}));const field=input("Authenticator code","text",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});root.append(field);primary(root,"Confirm authenticator",async()=>{const otp=field.querySelector("input").value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(otp)){state.error="Enter the 6 numbers from your authenticator, for example 123456.";render();return;}const r=await api("/api/mfa/confirm","POST",{otp});if(!r.ok){state.error=r.message;render();return;}state.mfa=true;state.secret="";state.error="";state.notice="Authenticator confirmed. Now save your recovery codes.";state.view="codes";render();});root.append(el("button",{class:"link",type:"button",onClick:()=>{state.view="home";state.error="";render();},text:"Back"}));help(root);}
function codes(root){header(root,4);root.append(el("h1",{text:"Save recovery codes"}),el("p",{text:"Each code works once if you cannot use your authenticator. Save them somewhere private."}));status(root);if(state.codes.length){const list=el("ul",{class:"codes","aria-label":"New recovery codes"});state.codes.forEach(c=>list.append(el("li",{text:c})));root.append(list,el("div",{class:"hint",text:"These are shown once. Copy or download them before leaving this screen."}));root.append(el("button",{class:"secondary",type:"button",onClick:()=>copyText(state.codes.join("\\n"),"Recovery codes copied."),text:"Copy all codes"}),el("button",{class:"secondary",type:"button",onClick:downloadCodes,text:"Download codes"}));primary(root,"I saved my codes",()=>{state.codes=[];state.notice="Recovery codes are ready when you need them.";state.view="home";render();});}else{root.append(el("div",{class:"hint",text:"Choose one action to make a new set. Any older recovery codes will stop working."}));primary(root,"Create recovery codes",generateCodes);}root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="recovery";state.error="";state.notice="";render();},text:"Use a recovery code"}));help(root);}
async function generateCodes(){const r=await api("/api/mfa/backup/regenerate","POST",{});if(!r.ok){state.error=r.message;render();return;}state.codes=r.codes;state.error="";state.notice="New recovery codes created. Save them now.";log("Mock backup recovery codes: "+r.codes.join(", "));render();}
function recovery(root){header(root,4);root.append(el("h1",{text:"Use a recovery code"}),el("p",{text:"Enter one unused recovery code. It will be used up after it works."}));status(root);const field=input("Recovery code","text",{autocomplete:"one-time-code",autocapitalize:"characters",placeholder:"Example: ABCD-EFGH-JKLM"});root.append(field,el("div",{class:"hint",text:"Use the dashes if they are shown. You can try another saved code if one was already used."}));primary(root,"Check recovery code",async()=>{const code=field.querySelector("input").value.trim().toUpperCase();if(!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)){state.error="Use this format: ABCD-EFGH-JKLM.";render();return;}const r=await api("/api/mfa/recovery/verify","POST",{code});if(!r.ok){state.error=r.message;render();return;}state.error="";state.notice="Recovery code accepted and used. Your MFA remains active.";state.view="home";render();});root.append(el("button",{class:"link",type:"button",onClick:()=>{state.view="home";state.error="";render();},text:"Back"}));help(root);}
async function copyText(value,message){try{await navigator.clipboard.writeText(value);state.notice=message;}catch{state.notice="Select the code and copy it using your browser controls.";}state.error="";render();}
function downloadCodes(){const content="Harbour Bank recovery codes\\nKeep these private. Each code works once.\\n\\n"+state.codes.join("\\n")+"\\n";const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type:"text/plain"}));a.download="harbour-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);state.notice="Recovery codes downloaded.";render();}
async function logout(){await api("/api/logout","POST",{});state.auth=false;state.mfa=false;state.secret="";state.codes=[];state.view="signin";state.notice="Signed out.";state.error="";render();}
async function boot(){const r=await api("/api/session");if(r.ok){state.csrf=r.csrf;state.auth=r.auth;state.mfa=r.mfa;if(r.auth)state.view="home";}else state.error="Please refresh the page.";render();}
boot();
})();
</script></body></html>`;
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      if (!trustedOrigin(request)) return genericError(request, 403, "This request is not allowed.");
      const headers = commonHeaders(request);
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers });
    }

    if (url.pathname === "/" && request.method === "GET") {
      const nonce = opaqueToken(18);
      const headers = commonHeaders(request, nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }

    if (!url.pathname.startsWith("/api/")) return genericError(request, 404, "Page not found.");

    if (url.pathname === "/api/session" && request.method === "GET") {
      let session = validSession(request);
      let cookie: string | undefined;
      if (!session) {
        session = createSession();
        cookie = sessionCookie(session);
      }
      return json(request, {
        ok: true,
        csrf: session.csrf,
        auth: session.phase === "auth" && session.userId === "marcus-account",
        mfa: session.mfaEnabled,
      }, 200, cookie);
    }

    if (url.pathname === "/api/signin/request" && request.method === "POST") {
      let session = validSession(request);
      let cookie: string | undefined;
      if (!session) {
        session = createSession();
        cookie = sessionCookie(session);
      }
      if (!csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request);
      const email = typeof data?.email === "string" ? data.email.trim().toLowerCase() : "";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) || email.length > 120) {
        return genericError(request, 400, "Enter an email in this format: name@example.com.");
      }
      session.email = email;
      session.identityCode = createIdentityCode();
      session.identityExpires = Date.now() + CHALLENGE_MS;
      session.identityUsed = false;
      session.identityFailures = 0;
      session.identityLockedUntil = undefined;
      // Academic mock delivery value: deliberately returned only to its current browser flow.
      return json(request, { ok: true, mockCode: session.identityCode }, 200, cookie);
    }

    if (url.pathname === "/api/signin/verify" && request.method === "POST") {
      const session = validSession(request);
      if (!session || !csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request);
      const code = typeof data?.code === "string" ? data.code : "";
      const now = Date.now();
      if (session.identityLockedUntil && now < session.identityLockedUntil) {
        return genericError(request, 429, "Too many incorrect codes. Wait a few minutes, then request a new code.");
      }
      if (!/^\d{6}$/.test(code)) return genericError(request, 400, "Enter all 6 numbers from the code.");
      if (!session.identityCode || session.identityUsed || !session.identityExpires || now > session.identityExpires) {
        return genericError(request, 400, "That code is no longer available. Request a new code and try again.");
      }
      if (!timingSafeEqual(Buffer.from(code), Buffer.from(session.identityCode))) {
        session.identityFailures++;
        if (session.identityFailures >= 5) session.identityLockedUntil = now + LOCK_MS;
        return genericError(request, 400, "That code did not match. Check the 6 numbers or request another code.");
      }
      session.identityUsed = true;
      sessions.delete(session.id); // Security §5: rotate identifier after authentication.
      const authenticatedSession = createSession("auth", "marcus-account");
      return json(request, { ok: true, csrf: authenticatedSession.csrf, mfa: false }, 200, sessionCookie(authenticatedSession));
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const session = validSession(request);
      if (!session || !csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      sessions.delete(session.id);
      return json(request, { ok: true }, 200, clearCookie());
    }

    if (url.pathname === "/api/mfa/enroll" && request.method === "POST") {
      const session = authenticated(request);
      if (!session) return genericError(request, 401, "Please sign in again to continue.");
      if (!csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      const secret = base32Secret();
      const mockOtp = "246810";
      session.enrollment = {
        secret: encrypt(secret), // Security §3: encrypted at rest in server memory.
        otpHash: createHash("sha256").update(mockOtp).digest(),
        consumed: false,
        failures: 0,
      };
      // No server logging of secrets. URI stays in the response for the current owner only.
      return json(request, {
        ok: true,
        secret,
        provisioningUri: `otpauth://totp/Harbour%20Bank:Marcus?secret=${secret}&issuer=Harbour%20Bank`,
        mockOtp,
      });
    }

    if (url.pathname === "/api/mfa/confirm" && request.method === "POST") {
      const session = authenticated(request);
      if (!session) return genericError(request, 401, "Please sign in again to continue.");
      if (!csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request);
      const otp = typeof data?.otp === "string" ? data.otp : "";
      const enrollment = session.enrollment;
      const now = Date.now();
      if (!enrollment) return genericError(request, 400, "Start authenticator setup first, then enter its code.");
      if (enrollment.lockedUntil && now < enrollment.lockedUntil) {
        return genericError(request, 429, "Too many incorrect codes. Wait a few minutes, then start setup again.");
      }
      if (!/^\d{6}$/.test(otp)) return genericError(request, 400, "Enter the 6 numbers from your authenticator.");
      const submitted = createHash("sha256").update(otp).digest();
      if (enrollment.consumed || !timingSafeEqual(submitted, enrollment.otpHash)) {
        enrollment.failures++;
        if (enrollment.failures >= 5) enrollment.lockedUntil = now + LOCK_MS;
        return genericError(request, 400, "That authenticator code did not match. Check it, or start setup again.");
      }
      enrollment.consumed = true;
      session.mfaEnabled = true;
      return json(request, { ok: true });
    }

    if (url.pathname === "/api/mfa/backup/regenerate" && request.method === "POST") {
      const session = authenticated(request);
      if (!session) return genericError(request, 401, "Please sign in again to continue.");
      if (!csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      if (!session.mfaEnabled) return genericError(request, 400, "Confirm your authenticator before creating recovery codes.");
      const codes = issueBackupCodes(session); // Security §3: PBKDF2 hashes only are retained.
      return json(request, { ok: true, codes });
    }

    if (url.pathname === "/api/mfa/recovery/verify" && request.method === "POST") {
      const session = authenticated(request);
      if (!session) return genericError(request, 401, "Please sign in again to continue.");
      if (!csrf(request, session)) return genericError(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request);
      const code = typeof data?.code === "string" ? data.code.trim().toUpperCase() : "";
      const now = Date.now();
      if (session.recoveryLockedUntil && now < session.recoveryLockedUntil) {
        return genericError(request, 429, "Too many incorrect codes. Wait a few minutes, then try a saved code.");
      }
      if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) {
        return genericError(request, 400, "Use this format: ABCD-EFGH-JKLM.");
      }
      let matched: BackupCode | undefined;
      for (const candidate of session.backupCodes) {
        if (!candidate.used && candidate.expiresAt > now && hashesMatch(code, candidate.salt, candidate.hash)) {
          matched = candidate;
          break;
        }
      }
      if (!matched) {
        session.recoveryFailures++;
        if (session.recoveryFailures >= 5) session.recoveryLockedUntil = now + LOCK_MS;
        return genericError(request, 400, "That recovery code is unavailable. Try another saved, unused code or create new codes.");
      }
      matched.used = true; // Security §5: single use consumption.
      session.recoveryFailures = 0;
      return json(request, { ok: true });
    }

    return genericError(request, 404, "Page not found.");
  } catch {
    // Security §2: no diagnostic details or stack traces reach the browser.
    return genericError(request, 500, "We could not complete that step. Please try again.");
  }
}

if (!existsSync("certs/cert.pem") || !existsSync("certs/key.pem")) {
  throw new Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
}

Bun.serve({
  port: PORT,
  tls: {
    cert: readFileSync("certs/cert.pem"),
    key: readFileSync("certs/key.pem"),
  },
  fetch: handler,
});
