
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem
*/
const encoder = new TextEncoder();
const TEST_MOCK_LOGGING = Bun.env.MFA_TEST_MOCK_LOGGING === "1";
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, MAX_FAILURES = 5, LOCKOUT = 5 * 60_000;
const encKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));
const TEST_SECRET = "JBSWY3DPEHPK3PXP";
const TEST_CODES = ["A1B2C-3D4E5","F6G7H-8J9K0","LMN1P-2Q3R4","S5T6U-7V8W9","X0Y1Z-2A3B4","C5D6E-7F8G9","H1J2K-3L4M5","N6P7Q-8R9S0","T1U2V-3W4X5","Y6Z7A-8B9C0"];

function hash(v:string) { return Bun.CryptoHasher.hash("sha256", v, "hex"); }
function random(bytes=32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url"); }
function same(a:string,b:string) {
  const x=encoder.encode(a), y=encoder.encode(b); let d=x.length^y.length;
  for(let i=0;i<Math.max(x.length,y.length);i++) d|=(x[i]||0)^(y[i]||0);
  return d===0;
}
async function hmac(v:string) {
  const k=await crypto.subtle.importKey("raw",recoveryKey,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC",k,encoder.encode(v))).toString("hex");
}
async function encrypt(v:string) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await crypto.subtle.importKey("raw",encKey,{name:"AES-GCM"},false,["encrypt"]);
  return {iv:Buffer.from(iv).toString("base64url"),data:Buffer.from(await crypto.subtle.encrypt({name:"AES-GCM",iv},k,encoder.encode(v))).toString("base64url")};
}
async function decrypt(v:any) {
  const k=await crypto.subtle.importKey("raw",encKey,{name:"AES-GCM"},false,["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:Buffer.from(v.iv,"base64url")},k,Buffer.from(v.data,"base64url")));
}
function secret() {
  if(TEST_MOCK_LOGGING)return TEST_SECRET;
  const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let s="";
  while(s.length<32) for(const b of crypto.getRandomValues(new Uint8Array(32))) if(b<224&&s.length<32)s+=a[b%32];
  return s;
}
function codes() {
  if(TEST_MOCK_LOGGING)return [...TEST_CODES];
  const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", out=new Set<string>();
  while(out.size<10) {
    let s=""; while(s.length<10) for(const b of crypto.getRandomValues(new Uint8Array(20)))if(b<252&&s.length<10)s+=a[b%36];
    out.add(s.slice(0,5)+"-"+s.slice(5));
  }
  return [...out];
}
function base32(v:string) {
  const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let bits=0,n=0,out:number[]=[];
  for(const c of v.replace(/=|\s/g,"").toUpperCase()){const x=a.indexOf(c);if(x<0)throw Error();bits=(bits<<5)|x;n+=5;while(n>=8){n-=8;out.push((bits>>>n)&255);}}
  return new Uint8Array(out);
}
async function totp(s:string,c=Math.floor(Date.now()/30000)) {
  const d=new Uint8Array(8);let n=BigInt(c);for(let i=7;i>=0;i--){d[i]=Number(n&255n);n>>=8n;}
  const k=await crypto.subtle.importKey("raw",base32(s),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const h=new Uint8Array(await crypto.subtle.sign("HMAC",k,d)), o=h[19]&15;
  return String((((h[o]&127)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3])%1000000).padStart(6,"0");
}
accounts.set("marcus-account-001",{id:"marcus-account-001",email:"marcus@example.com",passwordHash:hash("BankDemo!42"),mfaEnabled:false,pending:null,active:null,usedTotp:[],backup:[],usedBackup:[],otpFailures:0,otpLocked:0,recoveryFailures:0,recoveryLocked:0,replacing:false});
const dummyHash=hash("not-an-account-password");

function getCookies(r:Request) {
  const out:any={};for(const p of (r.headers.get("cookie")||"").split(";")){const i=p.indexOf("=");if(i>0)out[p.slice(0,i).trim()]=p.slice(i+1).trim();}return out;
}
function trusted(h:string){return h==="localhost"||h==="127.0.0.1"||h==="::1"||h==="[::1]";}
function sameOrigin(r:Request){const u=new URL(r.url);return u.protocol==="https:"&&trusted(u.hostname)&&r.headers.get("origin")===u.origin;}
function secureHeaders(r:Request,nonce="") {
  const h=new Headers({"Content-Security-Policy":`default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,"Strict-Transport-Security":"max-age=31536000; includeSubDomains","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store"});
  if(sameOrigin(r)){h.set("Access-Control-Allow-Origin",new URL(r.url).origin);h.set("Access-Control-Allow-Credentials","true");h.set("Vary","Origin");}
  return h;
}
function reply(r:Request,data:any,status=200,extra?:HeadersInit) {
  const h=secureHeaders(r);h.set("Content-Type","application/json; charset=utf-8");if(extra)new Headers(extra).forEach((v,k)=>h.set(k,v));
  return new Response(JSON.stringify(data),{status,headers:h});
}
async function payload(r:Request){try{const x=await r.json();return x&&typeof x==="object"&&!Array.isArray(x)?x:any;}catch{return null;}}
function owner(r:Request) {
  const id=getCookies(r).mfa_session, s=id&&sessions.get(id), now=Date.now();
  if(!s||now-s.last> IDLE||now-s.created>ABSOLUTE){if(id)sessions.delete(id);return null;}
  const account=accounts.get(s.userId);if(!account)return null;s.last=now;return {id,s,account};
}
function cookie(id:string){return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE/1000}`;}
function validOtp(x:any){return typeof x==="string"&&/^\d{6}$/.test(x);}
function validCode(x:any){return typeof x==="string"&&/^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(x);}
function failRecovery(r:Request,a:any,text:string) {
  a.recoveryFailures++;
  if(a.recoveryFailures>=MAX_FAILURES){a.recoveryLocked=Date.now()+LOCKOUT;return reply(r,{ok:false,message:"Too many recovery-code attempts. Try again in five minutes."},429);}
  return reply(r,{ok:false,message:`${text} Please try again. ${MAX_FAILURES-a.recoveryFailures} attempts remain before a short lockout.`},400);
}

/* Requirement 1: authenticated owner and CSRF validation are required for every MFA route. */
async function handle(r:Request):Promise<Response> {
  const u=new URL(r.url);
  if(u.protocol!=="https:"||!trusted(u.hostname))return new Response("Not found",{status:404,headers:secureHeaders(r)});
  if(r.method==="GET"&&u.pathname==="/"){const n=random(18),h=secureHeaders(r,n);h.set("Content-Type","text/html; charset=utf-8");return new Response(page(n),{headers:h});}

  if(r.method==="POST"&&u.pathname==="/api/signin") {
    if(!sameOrigin(r))return reply(r,{ok:false,message:"Please use the secure sign-in page."},403);
    const d=await payload(r), email=typeof d?.email==="string"?d.email.trim().toLowerCase():"", password=d?.password;
    const account=[...accounts.values()].find(a=>a.email===email);
    const ok=account&&typeof password==="string"&&password.length>=8&&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)&&same(hash(password),account.passwordHash);
    if(!ok){same(hash(typeof password==="string"?password:""),dummyHash);return reply(r,{ok:false,message:"Sign-in could not be completed. Check your email and password, then try again."},401);}
    for(const [id,s] of sessions)if(s.userId===account.id)sessions.delete(id);
    const id=random(),s={userId:account.id,csrf:random(24),created:Date.now(),last:Date.now()};sessions.set(id,s);
    return reply(r,{ok:true,csrf:s.csrf,mfaEnabled:account.mfaEnabled},200,{"Set-Cookie":cookie(id)});
  }

  const current=owner(r);
  if(!current)return reply(r,{ok:false,message:"Please sign in again to continue."},401);
  if(r.method!=="POST"||!sameOrigin(r)||r.headers.get("x-csrf-token")!==current.s.csrf)return reply(r,{ok:false,message:"Please refresh the secure page and try again."},403);
  const a=current.account;

  if(u.pathname==="/api/logout"){sessions.delete(current.id);return reply(r,{ok:true},200,{"Set-Cookie":"mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"});}
  if(u.pathname==="/api/begin-reenrolment"){if(!a.mfaEnabled)return reply(r,{ok:false,message:"Finish setup first."},400);a.replacing=true;return reply(r,{ok:true});}
  if(u.pathname==="/api/provision"){
    if(a.mfaEnabled&&!a.replacing)return reply(r,{ok:false,message:"Choose Replace authenticator first."},400);
    const s=secret();a.pending=await encrypt(s);a.usedTotp=[];
    const uri="otpauth://totp/"+encodeURIComponent("Northstar Bank:"+a.email)+"?secret="+s+"&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";
    const out:any={ok:true,secret:s,uri,message:"Authenticator setup is ready."};if(TEST_MOCK_LOGGING)out.verificationCode=await totp(s);return reply(r,out);
  }
  if(u.pathname==="/api/verify-otp"){
    const d=await payload(r),now=Date.now();if(!validOtp(d?.otp))return reply(r,{ok:false,message:"Enter exactly six numbers, for example 123456."},400);
    if(a.otpLocked>now)return reply(r,{ok:false,message:"Too many attempts. Please wait a few minutes."},429);
    if(a.otpLocked){a.otpLocked=0;a.otpFailures=0;}if(!a.pending)return reply(r,{ok:false,message:"Request a new setup and try again."},400);
    const s=await decrypt(a.pending),base=Math.floor(now/30000);let hit=-1;
    for(let c=base-1;c<=base+1;c++)if(c>=0&&!a.usedTotp.includes(c)&&same(await totp(s,c),d.otp)){hit=c;break;}
    if(hit<0){if(++a.otpFailures>=MAX_FAILURES)a.otpLocked=now+LOCKOUT;return reply(r,{ok:false,message:"That code did not match, was used, or is no longer current. Try again."},400);}
    a.usedTotp.push(hit);a.active=a.pending;a.pending=null;a.mfaEnabled=true;a.replacing=false;a.otpFailures=0;a.otpLocked=0;
    const c=codes();a.backup=await Promise.all(c.map(hmac));a.usedBackup=[];a.recoveryFailures=0;a.recoveryLocked=0;
    const out:any={ok:true,codes:c};if(TEST_MOCK_LOGGING)out.testCodes=c;return reply(r,out);
  }
  if(u.pathname==="/api/regenerate-backup-codes"){
    if(!a.mfaEnabled)return reply(r,{ok:false,message:"Finish setup first."},400);
    const c=codes();a.backup=await Promise.all(c.map(hmac));a.usedBackup=[];a.recoveryFailures=0;a.recoveryLocked=0;const out:any={ok:true,codes:c};if(TEST_MOCK_LOGGING)out.testCodes=c;return reply(r,out);
  }
  if(u.pathname==="/api/verify-recovery-code"){
    const now=Date.now();if(a.recoveryLocked>now)return reply(r,{ok:false,message:"Recovery verification is locked for five minutes. Please try again later."},429);
    if(a.recoveryLocked){a.recoveryLocked=0;a.recoveryFailures=0;}const d=await payload(r);
    if(!validCode(d?.code))return failRecovery(r,a,"Use five capital letters or numbers, a hyphen, then five more. Example: AAAAA-BBBBB.");
    const v=await hmac(d.code);let i=-1,used=false;a.backup.forEach((x:string,n:number)=>{if(same(x,v))i=n;});a.usedBackup.forEach((x:string)=>{if(same(x,v))used=true;});
    if(i>=0){a.usedBackup.push(a.backup.splice(i,1)[0]);a.recoveryFailures=0;return reply(r,{ok:true,message:"Recovery code accepted. That code is now used and cannot be used again."});}
    return failRecovery(r,a,used?"This recovery code was already used. Use a different saved code.":"This recovery code does not match one of your saved codes.");
  }
  return new Response("Not found",{status:404,headers:secureHeaders(r)});
}

function page(nonce:string){return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--bad:#8b2424;--good:#125b35}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:16px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 28px}header{display:flex;gap:10px;align-items:center}.mark{background:var(--blue);color:#fff;border-radius:12px;padding:8px 14px;font-size:22px}h1{font-size:1.35rem;margin:0}h2{line-height:1.3;margin-top:0}.hint{color:#526273;font-size:.88rem}.steps{display:flex;gap:4px;margin:18px 0}.steps span{flex:1;border-bottom:4px solid var(--line);font-size:.72rem;text-align:center;padding-bottom:4px}.steps .on{border-color:var(--blue);color:#073c83;font-weight:bold}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:20px}.notice{padding:11px;border-radius:9px;background:var(--soft);margin:12px 0}.bad{background:#fff0f0;color:var(--bad)}.success{background:#effaf2;color:var(--good)}label{display:block;font-weight:bold;margin:15px 0 5px}input,button{width:100%;min-height:52px;border-radius:10px;font:inherit}input{border:2px solid #9eafc0;padding:10px;letter-spacing:.05em}button{border:0;padding:10px;margin-top:12px;font-weight:bold;cursor:pointer}.primary{background:var(--blue);color:#fff}.secondary{background:#fff;color:#073c83;border:2px solid var(--blue)}button:focus,input:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}.secret,.code,#logs-output{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px}.row button{flex:1}.qr{width:250px;height:250px;margin:15px auto;border:12px solid white;background:repeating-linear-gradient(90deg,#111 0 4px,#fff 4px 8px),repeating-linear-gradient(#111 0 4px,#fff 4px 8px);opacity:.9}.logs{margin-top:16px;padding:14px}.logs h2{font-size:1rem;margin-bottom:8px}#logs-output{white-space:pre-wrap;min-height:42px;font-size:.78rem;line-height:1.45}@media(max-width:390px){.codes{grid-template-columns:1fr}.row{flex-direction:column}}
</style></head><body><main><header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><div class="hint">Security setup</div></div></header><nav class="steps" aria-label="Setup steps"><span data-s="1">1. Confirm</span><span data-s="2">2. App</span><span data-s="3">3. Check</span><span data-s="4">4. Save</span></nav><section id="app" class="card" aria-live="polite"></section><p class="hint">Take your time. There is no reading timer.</p><aside class="logs" aria-label="Logs"><h2>Logs</h2><div id="logs-output">Ready.</div></aside></main>
<script nonce="${nonce}">
"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs-output"),TEST=${TEST_MOCK_LOGGING?"true":"false"};let csrf="",s="",uri="",backup=[];
function esc(v){const x=document.createElement("span");x.textContent=String(v);return x.innerHTML}
function log(a,v){console.log(a,v===undefined?"":v);logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+a+(v===undefined?"":" "+(Array.isArray(v)?v.join(", "):v))}
function step(n){document.querySelectorAll("[data-s]").forEach(x=>x.classList.toggle("on",+x.dataset.s===n))}
function note(t,k=""){return '<div class="notice '+k+'">'+esc(t)+"</div>"}
function help(){return "<details><summary>Help with this step</summary><p>Pause or retry at any time. There is no reading timer.</p></details>"}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)}),d=await r.json().catch(()=>({message:"Please try again."}));if(r.status===401)signin("Your session ended. Please sign in again.");return {r,d}}
async function copy(v,name){try{await navigator.clipboard.writeText(v);document.querySelector("#msg").textContent=name+" copied. You can paste it somewhere safe."}catch{document.querySelector("#msg").textContent="Copy did not work here. You can select the text and copy it instead."}}
function signin(msg=""){step(1);app.innerHTML="<h2>Confirm your account</h2><p>Use your bank email and password.</p>"+(TEST?note("Test mode is on. Mock values are shown in Logs.","success"):"")+(msg?note(msg):"")+'<label>Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label>Password</label><input id="password" type="password" autocomplete="current-password"><button class="primary" id="go">Continue</button>'+help();document.querySelector("#go").onclick=async()=>{const r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email.value,password:password.value})}),d=await r.json();if(!r.ok){app.insertAdjacentHTML("afterbegin",note(d.message,"bad"));return}csrf=d.csrf;log("Sign-in simulation completed.");d.mfaEnabled?account("Your authenticator is active."):setup("Your identity is confirmed. Next, add your authenticator app.");}}
function setup(m){step(2);app.innerHTML="<h2>Add your authenticator app</h2>"+note(m)+"<p>Open your authenticator app. You can scan a setup image or copy a secret.</p><button class='primary' id='show'>Show secure setup</button>"+help();show.onclick=provision}
async function provision(){const x=await api("/api/provision");if(!x.r.ok){app.insertAdjacentHTML("afterbegin",note(x.d.message,"bad"));return}s=x.d.secret;uri=x.d.uri;log("Authenticator provisioning simulation completed.");if(x.d.verificationCode)log("Mock TOTP test value:",x.d.verificationCode);step(2);app.innerHTML="<h2>Your setup is ready</h2>"+note(x.d.message)+"<p>Scan this QR-style setup image, or copy the secret below.</p><div class='qr' aria-label='Authenticator setup QR option'></div><div class='secret'>"+esc(s)+"</div><div class='row'><button class='secondary' id='copy'>Copy secret</button><button class='secondary' id='link'>Show setup link</button></div><div id='full' hidden class='secret'>"+esc(uri)+"</div><button class='primary' id='added'>I added it to my app</button><div id='msg' class='hint'></div>"+help();copy.onclick=()=>copy(s,"Authenticator secret");link.onclick=()=>{full.hidden=!full.hidden;link.textContent=full.hidden?"Show setup link":"Hide setup link"};added.onclick=verify}
function verify(){step(3);app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your authenticator app.</p><label>Six-digit code</label><input id='otp' inputmode='numeric' autocomplete='one-time-code' maxlength='6' placeholder='123456'><p class='hint'>Example: 123456. You have plenty of time.</p><button class='primary' id='check'>Verify code</button>"+help();check.onclick=async()=>{const x=await api("/api/verify-otp",{otp:otp.value.trim()});if(!x.r.ok){app.insertAdjacentHTML("afterbegin",note(x.d.message,"bad"));return}backup=x.d.codes;log("Authenticator verification simulation succeeded.");if(x.d.testCodes)log("Mock recovery codes:",x.d.testCodes);save("Your authenticator is now connected.");}}
function save(m){step(4);app.innerHTML="<h2>Save your recovery codes</h2>"+note(m,"success")+"<p>Store these somewhere safe. Each code works once.</p><div class='codes'>"+backup.map(x=>"<div class='code'>"+esc(x)+"</div>").join("")+"</div><button class='secondary' id='all'>Copy all recovery codes</button><div id='msg' class='hint'></div><button class='primary' id='saved'>I saved my codes</button>"+help();all.onclick=()=>copy(backup.join("\\n"),"All recovery codes");saved.onclick=()=>account("Your recovery codes are saved.")}
function account(m){step(4);app.innerHTML="<h2>Security setup</h2>"+note(m,"success")+"<p>Your authenticator is active.</p><button class='primary' id='recover'>Use a recovery code</button><button class='secondary' id='replace'>Replace authenticator</button><button class='secondary' id='new'>Generate new recovery codes</button><button class='secondary' id='out'>Sign out</button>"+help();recover.onclick=recovery;replace.onclick=async()=>{const x=await api("/api/begin-reenrolment");x.r.ok?setup("Replacement started. Your current authenticator remains active until checked."):account(x.d.message)};new.onclick=async()=>{const x=await api("/api/regenerate-backup-codes");if(x.r.ok){backup=x.d.codes;log("Recovery-code generation simulation completed.");save("New recovery codes replaced the old ones.")}};out.onclick=async()=>{await api("/api/logout");csrf="";log("Sign-out simulation completed.");signin("You have signed out safely.")}}
function recovery(m="",k=""){step(4);app.innerHTML="<h2>Use a recovery code</h2>"+(m?note(m,k):"")+"<p>Use one saved recovery code when you need to check that it works.</p><label>Recovery code</label><input id='rc' autocomplete='one-time-code' maxlength='11' placeholder='AAAAA-BBBBB'><p class='hint'>Example: AAAAA-BBBBB</p><button class='primary' id='vr'>Verify recovery code</button><button class='secondary' id='back'>Back to security setup</button>"+help();rc.oninput=()=>rc.value=rc.value.toUpperCase().replace(/[^A-Z0-9-]/g,"").slice(0,11);back.onclick=()=>account("Your authenticator is active.");vr.onclick=async()=>{const x=await api("/api/verify-recovery-code",{code:rc.value.trim()});if(x.r.ok)log("Recovery-code verification simulation succeeded.");recovery(x.d.message,x.r.ok?"success":"bad")}}
signin();
</script></body></html>`;}

Bun.serve({
  hostname:"localhost",
  port:Number(Bun.env.PORT||3000),
  tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
  async fetch(request){try{return await handle(request);}catch{return new Response("Something went wrong. Please try again.",{status:500,headers:secureHeaders(request)});}}
});
console.log("MFA HTTPS server running at https://localhost:"+(Bun.env.PORT||3000));
