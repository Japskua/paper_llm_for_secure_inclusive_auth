
import { serve, file } from "bun";

/* MFA Requirements 1–5: in-memory, HTTPS-only academic simulation.
   Secrets/codes are generated with Web Crypto, encrypted/hashed at rest, and
   returned only in the authenticated active-flow response. Never server-logged. */
const PORT = 3000;
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 10 * 60_000;
const LOCK = 5 * 60_000, MAX = 5;
const trustedOrigins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

type Challenge = { hash: string; expires: number; used: boolean };
type Session = { id:string; csrf:string; created:number; seen:number; user?:string; identity:boolean; identityCode?:Challenge; authCode?:Challenge };
type Account = {
  id:string; email:string; otp?:{iv:string;data:string}; recovery:Set<string>;
  recoveryExpires?:number; recoveryFailures:number; recoveryLocked:number;
  generated:boolean; confirmed:boolean; mfa:boolean; setup:boolean;
  identityFailures:number; identityLocked:number; authFailures:number; authLocked:number;
};
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const loginFailures = new Map<string, { failures:number; locked:number }>();
const aesKey = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
const pepper = secureHex(32);

accounts.set("marcus-account", {
  id:"marcus-account", email:"marcus@example.com", recovery:new Set(), recoveryFailures:0, recoveryLocked:0,
  generated:false, confirmed:false, mfa:false, setup:false, identityFailures:0, identityLocked:0,
  authFailures:0, authLocked:0
});

function bytes(n:number) { const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
function secureHex(n:number) { return [...bytes(n)].map(x=>x.toString(16).padStart(2,"0")).join(""); }
function randomFrom(chars:string, length:number) {
  const out:string[] = [], limit = 256 - (256 % chars.length);
  while (out.length < length) for (const b of bytes(length * 2)) if (b < limit) {
    out.push(chars[b % chars.length]); if (out.length === length) break;
  }
  return out.join("");
}
/* Task: all challenge and recovery values use cryptographically secure randomness. */
function otp() { return randomFrom("0123456789", 6); }
function base32Secret() { return randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32); }
function recoveryCode() { return [0,1,2].map(()=>randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",4)).join("-"); }
function recoverySet() { const set=new Set<string>(); while(set.size<8) set.add(recoveryCode()); return [...set]; }
function b64(v:Uint8Array) { return Buffer.from(v).toString("base64"); }
async function hash(v:string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pepper+":"+v)))); }
async function encrypt(v:string) {
  const iv=bytes(12), data=await crypto.subtle.encrypt({name:"AES-GCM",iv},aesKey,new TextEncoder().encode(v));
  return {iv:b64(iv),data:b64(new Uint8Array(data))};
}
function equal(a:string,b:string) {
  const x=new TextEncoder().encode(a), y=new TextEncoder().encode(b); if(x.length!==y.length)return false;
  let d=0; for(let i=0;i<x.length;i++)d|=x[i]^y[i]; return d===0;
}
function getCookie(req:Request,name:string) {
  for(const p of (req.headers.get("cookie")||"").split(";")) { const [k,...v]=p.trim().split("="); if(k===name)return decodeURIComponent(v.join("=")); }
}
function newSession():Session { const now=Date.now(); return {id:secureHex(32),csrf:secureHex(32),created:now,seen:now,identity:false}; }
function cookie(id:string, age=ABSOLUTE) { return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(age/1000)}`; }
function current(req:Request) {
  const s=getCookie(req,"mfa_session"), found=s&&sessions.get(s);
  if(!found)return;
  if(Date.now()-found.seen>IDLE || Date.now()-found.created>ABSOLUTE) { sessions.delete(found.id); return; }
  found.seen=Date.now(); return found;
}
function headers(nonce?:string) {
  const h=new Headers({"Content-Type":"application/json; charset=utf-8","Strict-Transport-Security":"max-age=31536000; includeSubDomains","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store","Permissions-Policy":"camera=(), microphone=(), geolocation=()"});
  h.set("Content-Security-Policy",nonce?`default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`:"default-src 'none'; frame-ancestors 'none'");
  return h;
}
function json(v:unknown,status=200,h=headers()) { return new Response(JSON.stringify(v),{status,headers:h}); }
function fail(message="We could not complete that step. Please try again.",status=400) { return json({ok:false,message},status); }
async function body(req:Request):Promise<Record<string,unknown>|null> { try { const x=await req.json(); return x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:null; } catch{return null;} }
function csrf(req:Request,s:Session) { const v=req.headers.get("x-csrf-token"); return !!v&&equal(v,s.csrf); }
function owner(req:Request):{s:Session;a:Account}|Response {
  const s=current(req); if(!s?.user)return fail("Please sign in again to continue.",401);
  const a=accounts.get(s.user); return a?{s,a}:fail("Please sign in again to continue.",401);
}
function verified(req:Request) { const r=owner(req); return r instanceof Response||r.s.identity?r:fail("Please finish identity check before changing MFA settings.",403); }
function state(s:Session,a?:Account) { return {ok:true,csrf:s.csrf,loggedIn:!!s.user,identityVerified:s.identity,mfaEnabled:!!a?.mfa,authenticatorSetupStarted:!!a?.setup,recoveryGenerated:!!a?.generated,recoveryConfirmed:!!a?.confirmed}; }
function six(v:unknown):v is string { return typeof v==="string"&&/^\d{6}$/.test(v); }
function rec(v:unknown):v is string { return typeof v==="string"&&/^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(v); }
function locked(a:Account, type:"identity"|"auth"|"recovery") { return type==="identity"?a.identityLocked:type==="auth"?a.authLocked:a.recoveryLocked; }

function page(nonce:string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Harbour Bank MFA</title>
<style nonce="${nonce}">:root{--b:#075fc6;--i:#172334;--m:#536276;--l:#cbd6e2}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--i);font:17px/1.65 Verdana,"Trebuchet MS",Arial,sans-serif;letter-spacing:.025em}main{max-width:560px;margin:auto;padding:18px 16px 35px}header{display:flex;gap:10px;align-items:center;margin-bottom:16px}.logo{background:var(--b);color:white;border-radius:50%;width:42px;height:42px;display:grid;place-items:center;font-weight:bold}h1{font-size:1.35rem;margin:0}h2{font-size:1.3rem;line-height:1.3;margin:0 0 8px}.card,.logs{background:white;border:1px solid var(--l);border-radius:14px;padding:20px 17px}.steps,.hint{color:var(--m);font-size:.9rem}.now{color:var(--b);font-weight:bold}.notice{background:#edf6ff;border-left:5px solid var(--b);border-radius:5px;padding:10px 12px;margin:14px 0}.error{background:#fff0f0;border-color:#a12828;color:#721b1b}.good{background:#effaf3;border-color:#146c43;color:#145535}label{display:block;font-weight:bold;margin:16px 0 5px}input{font:inherit;letter-spacing:.05em;width:100%;min-height:51px;padding:9px 11px;border:2px solid #91a5b9;border-radius:9px}input:focus{outline:3px solid #8ac5ff;border-color:var(--b)}button{font:inherit;letter-spacing:.02em;cursor:pointer;border-radius:9px;padding:10px 15px;min-height:45px}.primary{width:100%;margin-top:17px;background:var(--b);color:white;border:2px solid var(--b);font-weight:bold}.secondary,.link{margin-top:10px;background:white;color:#164f88;border:1px solid #62768b}.link{border:0;text-decoration:underline;min-height:auto}.row{display:flex;gap:8px;flex-wrap:wrap}.secret{font-family:monospace;word-break:break-all;background:#f5f7f9;border:1px solid var(--l);padding:10px;border-radius:8px}.qr{display:grid;grid-template-columns:repeat(21,10px);width:210px;margin:15px auto;border:8px solid white;outline:1px solid var(--l)}.q{height:10px;background:white}.q.on{background:#000}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:7px;font:14px monospace}.codes li{padding:8px;border:1px solid var(--l);border-radius:7px;text-align:center;background:#f5f7f9}.footer{display:flex;justify-content:space-between;margin:12px 2px}.logs{margin-top:15px;padding:13px}.logs h2{font-size:1rem}.logs p,#log{font-size:.76rem;color:var(--m);margin:0;white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto}details{margin-top:16px;border-top:1px solid var(--l);padding-top:10px}summary{color:#164f88;font-weight:bold;cursor:pointer}[hidden]{display:none!important}@media(max-width:360px){body{font-size:16px}.codes{grid-template-columns:1fr}}</style></head><body><main><header><div class="logo">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header><div id="app">Loading secure setup…</div><section class="logs"><h2>Logs</h2><p>Testing-only generated values appear here and in this browser console only.</p><div id="log"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";let token="",st,view="signin",idCode,setup,codes,shown=true;const A=document.getElementById("app"),L=document.getElementById("log");
const log=x=>{console.log(x);const d=document.createElement("div");d.textContent=x;L.append(d)};
async function api(p,m="GET",d){const o={method:m,headers:{}};if(m!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=token;o.body=JSON.stringify(d||{})}const r=await fetch(p,o),x=await r.json();if(x.csrf)token=x.csrf;if(!r.ok||!x.ok)throw Error(x.message);return x}
async function refresh(){st=await api("/api/state")} function msg(x){const e=document.getElementById("msg");e.textContent=x;e.hidden=false}
function shell(step,title,icon,txt,html){A.innerHTML='<div class="steps">Step <span class="now">'+step+'</span> of 5</div><section class="card"><h2>'+icon+" "+title+'</h2><p>'+txt+'</p><div id="msg" class="notice error" hidden></div>'+html+'<details><summary>Need help?</summary><p>Take your time. You can retry or request a new code without penalty.</p></details></section><nav class="footer"><button class="link" id="help">Help</button><button class="link" id="out">Log out</button></nav>';help.onclick=()=>{view="help";render()};out.onclick=logout}
function render(){({signin,identity,setupPage,confirm,backup,manage,recover,done,help}[view]||help)()}
function signin(){shell("1","Sign in","🔐","Use the email for your new bank account.",'<div class="notice">Practice sign-in: <code>marcus@example.com</code> and <code>bank-demo</code>.</div><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="marcus@example.com" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button class="primary">Continue</button></form>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/login","POST",{email:email.value,password:password.value});await refresh();log("SIMULATION: Sign-in accepted.");view=route();render()}catch(x){msg(x.message)}}}
function identity(){shell("2","Check it is you","✉️","We will send a short practice code to your account email.",'<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="send">Send my code</button>');send.onclick=async()=>{try{const x=await api("/api/identity/send","POST");idCode=x.testCode;log("TESTING ONLY — displayed identity OTP: "+idCode);identityEntry()}catch(e){msg(e.message)}}}
function identityEntry(){shell("2","Enter the email code","✉️","Enter the practice code shown in this browser.",'<div class="notice good">Practice email code: <code id="pc"></code></div><form id="f"><label>Email code<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><button class="primary">Check code</button></form><button class="secondary" id="again">Send a new code</button>');pc.textContent=idCode;f.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{code:code.value});idCode=null;await refresh();log("SIMULATION: Identity check completed.");view=route();render()}catch(x){msg(x.message)}};again.onclick=identity}
function qr(v){let n=0;for(const c of v)n=(n*31+c.charCodeAt(0))>>>0;let h="";for(let i=0;i<441;i++){n=(n*1664525+1013904223)>>>0;h+='<i class="q '+((n>>>30)&1?"on":"")+'"></i>'}return '<div class="qr" role="img" aria-label="Authenticator setup QR option">'+h+"</div>"}
function setupPage(){shell("3","Set up your authenticator","📱","Scan the code or copy the setup key into your authenticator app.",'<button class="primary" id="make">Show setup options</button>');make.onclick=async()=>{try{setup=await api("/api/authenticator/setup","POST");await refresh();log("TESTING ONLY — provisioning secret: "+setup.secret);log("TESTING ONLY — provisioning URI: "+setup.uri);log("TESTING ONLY — authenticator verification code: "+setup.testCode);options()}catch(e){msg(e.message)}}}
function options(){shell("3","Add this to your app","📱","Use the QR option, or paste this setup key manually.",qr(setup.uri)+'<label>Setup key</label><div class="secret" id="key"></div><div class="row"><button class="secondary" id="copy">Copy setup key</button><button class="secondary" id="hide">Hide key</button></div><div class="notice">Practice check code: <code id="tc"></code></div><button class="primary" id="ready">I added it to my app</button>');key.textContent=shown?setup.secret:"••••••••••••••••";tc.textContent=setup.testCode;copy.onclick=async()=>{try{await navigator.clipboard.writeText(setup.secret);log("SIMULATION: Setup key copied.")}catch{msg("Copy did not work. Select the key and copy it.")}};hide.onclick=()=>{shown=!shown;options()};ready.onclick=()=>{view="confirm";render()}}
function confirm(){shell("4","Check your authenticator","✅","Enter the 6-number practice code shown with your setup options.",'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><button class="primary">Check authenticator</button></form><button class="secondary" id="show">Show setup key again</button>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/confirm","POST",{code:code.value});setup=null;await refresh();log("SIMULATION: Authenticator confirmed.");view=route();render()}catch(x){msg(x.message)}};show.onclick=()=>setup?options():setupPage()}
function backup(){shell("5","Save backup codes","🧾","Keep these codes somewhere safe. Each code works once.",'<button class="primary" id="create">Show my backup codes</button>');create.onclick=generate}
async function generate(){try{const x=await api("/api/recovery/generate","POST",{confirmRegenerate:true});codes=x.codes;await refresh();log("TESTING ONLY — generated backup recovery codes: "+codes.join(", "));list()}catch(e){msg(e.message)}}
function list(){shell("5","Your backup codes","🧾","Copy or write down these short codes.",'<ul class="codes" id="list"></ul><button class="secondary" id="copy">Copy all codes</button><button class="primary" id="check">I saved them — check one</button>');codes.forEach(x=>{const i=document.createElement("li");i.textContent=x;list.append(i)});copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));log("SIMULATION: Backup codes copied.")}catch{msg("Copy did not work. Select the codes and copy them.")}};check.onclick=()=>{view="recover";render()}}
function manage(){shell("5","Manage backup codes","🧾","Codes cannot be shown again after leaving their screen.",'<div class="notice">Replacement codes permanently invalidate every old code.</div><button class="primary" id="regen">Generate replacement codes</button><button class="secondary" id="check">Check a saved code</button>');regen.onclick=()=>confirm("Replace all current backup codes?")&&generate();check.onclick=()=>{view="recover";render()}}
function recover(){shell("5","Check one backup code","🔎","Enter one unused backup code to confirm recovery.",'<form id="f"><label>Backup code<input id="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="14" placeholder="ABCD-EFGH-IJKL" required></label><button class="primary">Check backup code</button></form>'+(codes?'<button class="secondary" id="back">Show my codes again</button>':'<button class="secondary" id="back">Manage backup codes</button>'));f.onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify","POST",{code:code.value.toUpperCase()});codes=null;await refresh();log("SIMULATION: A backup code was checked and used once.");view=route();render()}catch(x){msg(x.message)}};back.onclick=()=>{if(codes)list();else{view="manage";render()}}}
function done(){shell("5","MFA is ready","🎉","Your authenticator is connected and backup codes are saved.",'<div class="notice good">Setup complete.</div><button class="primary" id="finish">Finish securely</button>');finish.onclick=logout}
function help(){shell("Help","Help with MFA","💡","Use one step at a time. Nothing on this page moves or times your reading.",'<button class="primary" id="return">Return to setup</button>');return.onclick=async()=>{await refresh();view=route();render()}}
function route(){return !st?.loggedIn?"signin":!st.identityVerified?"identity":!st.mfaEnabled?(st.authenticatorSetupStarted?"confirm":"setupPage"):!st.recoveryGenerated?"backup":!st.recoveryConfirmed?(codes?"recover":"manage"):"done"}
async function logout(){try{await api("/api/logout","POST")}catch{}token="";st=null;idCode=setup=codes=null;shown=true;log("SIMULATION: You have been logged out securely.");boot()}async function boot(){try{await refresh();view=route();render()}catch{A.textContent="We could not open secure setup. Please refresh this page."}}boot()})();</script></body></html>`; }

async function api(req:Request,path:string):Promise<Response> {
  const origin=req.headers.get("origin"); if(origin&&!trustedOrigins.has(origin))return fail("This request was not accepted. Please use this page directly.",403);
  if(path==="/api/state"&&req.method==="GET") { let s=current(req), c:string|undefined; if(!s){s=newSession();sessions.set(s.id,s);c=cookie(s.id)} const h=headers();if(c)h.set("Set-Cookie",c);return json(state(s,s.user?accounts.get(s.user):undefined),200,h); }
  if(path==="/api/login"&&req.method==="POST") {
    const old=current(req), b=await body(req); if(!old||!csrf(req,old))return fail("Please refresh the page and try again.",403);
    const email=typeof b?.email==="string"?b.email.trim().toLowerCase():"", pass=typeof b?.password==="string"?b.password:"", now=Date.now(), f=loginFailures.get(email)||{failures:0,locked:0};
    if(f.locked>now)return fail("Too many sign-in attempts. Please wait a few minutes, then try again.",429);
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email)||email.length>254||pass.length>256||email!=="marcus@example.com"||pass!=="bank-demo"){f.failures++;if(f.failures>=MAX){f.failures=0;f.locked=now+LOCK}loginFailures.set(email,f);return fail(f.locked?"Too many sign-in attempts. Please wait a few minutes, then try again.":"We could not sign you in. Check your email and password, then try again.",f.locked?429:401)}
    loginFailures.delete(email);sessions.delete(old.id);const s=newSession();s.user="marcus-account";sessions.set(s.id,s);const h=headers();h.set("Set-Cookie",cookie(s.id));return json(state(s,accounts.get(s.user)),200,h);
  }
  if(path==="/api/logout"&&req.method==="POST"){const s=current(req);if(!s||!csrf(req,s))return fail("Please refresh the page and try again.",403);sessions.delete(s.id);const h=headers();h.set("Set-Cookie",cookie("",0));return json({ok:true},200,h)}
  if(path==="/api/identity/send"&&req.method==="POST"){const r=owner(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);if(r.a.identityLocked>Date.now())return fail("Too many incorrect codes. Please wait a few minutes.",429);const code=otp();r.s.identityCode={hash:await hash(code),expires:Date.now()+LIFE,used:false};return json({ok:true,csrf:r.s.csrf,testCode:code})}
  if(path==="/api/identity/verify"&&req.method==="POST"){const r=owner(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);const b=await body(req),c=r.s.identityCode;if(!six(b?.code))return fail("Enter all 6 numbers from the email code.");if(r.a.identityLocked>Date.now())return fail("Too many incorrect codes. Please wait a few minutes.",429);if(!c||c.used||c.expires<Date.now())return fail("That code is no longer available. Send a new code and try again.");if(!equal(await hash(b.code),c.hash)){if(++r.a.identityFailures>=MAX){r.a.identityFailures=0;r.a.identityLocked=Date.now()+LOCK;return fail("Too many incorrect codes. Please wait a few minutes.",429)}return fail("That code does not match. Check the 6 numbers or send a new code.")}c.used=true;r.a.identityFailures=0;r.s.identity=true;return json(state(r.s,r.a))}
  if(path==="/api/authenticator/setup"&&req.method==="POST"){const r=verified(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);if(r.a.authLocked>Date.now())return fail("Too many incorrect codes. Please wait a few minutes.",429);const secret=base32Secret(), code=otp();r.a.otp=await encrypt(secret);r.a.setup=true;r.s.authCode={hash:await hash(code),expires:Date.now()+LIFE,used:false};return json({ok:true,csrf:r.s.csrf,secret,uri:`otpauth://totp/Harbour:marcus?secret=${secret}&issuer=Harbour`,testCode:code})}
  if(path==="/api/authenticator/confirm"&&req.method==="POST"){const r=verified(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);const b=await body(req),c=r.s.authCode;if(!six(b?.code))return fail("Enter the 6-number authenticator code.");if(r.a.authLocked>Date.now())return fail("Too many incorrect codes. Please wait a few minutes.",429);if(!c||c.used||c.expires<Date.now())return fail("Setup time has passed. Show setup options again.");if(!equal(await hash(b.code),c.hash)){if(++r.a.authFailures>=MAX){r.a.authFailures=0;r.a.authLocked=Date.now()+LOCK;return fail("Too many incorrect codes. Please wait a few minutes.",429)}return fail("That code does not match. Check it and try again.")}c.used=true;r.a.authFailures=0;r.a.mfa=true;return json(state(r.s,r.a))}
  if(path==="/api/recovery/generate"&&req.method==="POST"){const r=verified(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);if(!r.a.mfa)return fail("Finish authenticator setup before creating backup codes.",403);const b=await body(req);if(r.a.recovery.size&&b?.confirmRegenerate!==true)return fail("Please confirm that you want to replace your current backup codes.");const codes=recoverySet();r.a.recovery=new Set(await Promise.all(codes.map(hash)));r.a.recoveryExpires=Date.now()+365*24*60*60_000;r.a.recoveryFailures=0;r.a.recoveryLocked=0;r.a.generated=true;r.a.confirmed=false;return json({ok:true,csrf:r.s.csrf,codes})}
  if(path==="/api/recovery/verify"&&req.method==="POST"){const r=verified(req);if(r instanceof Response)return r;if(!csrf(req,r.s))return fail("Please refresh the page and try again.",403);const b=await body(req),a=r.a;if(!a.generated)return fail("Create backup codes before checking one.",403);if(!rec(b?.code))return fail("Enter a backup code in this format: ABCD-EFGH-IJKL.");if(a.recoveryLocked>Date.now())return fail("Too many incorrect backup codes. Please wait a few minutes.",429);if(!a.recoveryExpires||a.recoveryExpires<Date.now())return fail("These backup codes have expired. Generate a new set.");const candidate=await hash(b.code);let found:string|undefined;for(const x of a.recovery)if(equal(x,candidate)){found=x;break}if(!found){if(++a.recoveryFailures>=MAX){a.recoveryFailures=0;a.recoveryLocked=Date.now()+LOCK;return fail("Too many incorrect backup codes. Please wait a few minutes.",429)}return fail("That backup code is not available. Check the code and try another saved code.")}a.recovery.delete(found);a.recoveryFailures=0;a.confirmed=true;return json(state(r.s,a))}
  return fail("This secure page is not available.",404);
}

serve({port:PORT,tls:{cert:file("certs/cert.pem"),key:file("certs/key.pem")},async fetch(req){try{const u=new URL(req.url);if(u.protocol!=="https:")return fail("Please use the secure HTTPS address.",403);if(u.pathname.startsWith("/api/"))return await api(req,u.pathname);if(u.pathname==="/"&&req.method==="GET"){const n=secureHex(18),h=headers(n);h.set("Content-Type","text/html; charset=utf-8");return new Response(page(n),{headers:h})}return fail("This secure page is not available.",404)}catch{return fail("We could not complete that request. Please try again.",500)}}});
