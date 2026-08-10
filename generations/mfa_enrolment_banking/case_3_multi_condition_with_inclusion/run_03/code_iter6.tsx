
/*
  MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
  Run: bun app.ts
  Requirements 1–5: server-side sessions, CSRF, TLS, encrypted secrets,
  PBKDF2 recovery-code storage, validation, lockouts, and safe headers.
*/
const PORT = Number(Bun.env.PORT || 3000);
const KEY = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const TEST_OTP = "654321";
/* Deterministic browser test values. They are one-use when verified. */
const TEST_RECOVERY = ["DEMO-0001-AAAA","DEMO-0002-BBBB","DEMO-0003-CCCC","DEMO-0004-DDDD","DEMO-0005-EEEE","DEMO-0006-FFFF","DEMO-0007-GGGG","DEMO-0008-HHHH"];
const DEMO = { id:"account-marcus-demo", email:"marcus@example.com", phone:"07123456789", password:"MarcusDemo!54" };
const IDLE = 20*60*1000, ABSOLUTE = 8*60*60*1000, LOCK = 5*60*1000, MAX = 5, REISSUE = 10*60*1000;

const token=(n=32)=>Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const email=(x:any)=>typeof x==="string"&&x.length<121&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const phone=(x:any)=>typeof x==="string"&&/^[0-9 +()\-]{7,25}$/.test(x);
const otp=(x:any)=>typeof x==="string"&&/^\d{6}$/.test(x);
const recovery=(x:any)=>typeof x==="string"&&/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x);
const normPhone=(x:string)=>x.replace(/\D/g,""), normEmail=(x:string)=>x.trim().toLowerCase();
const noId=(b:any)=>b&&!["userId","accountId","emailOwner"].some(k=>k in b);
async function digest(x:string){return Buffer.from(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(x))).toString("base64url")}
async function enc(value:string){
 const iv=crypto.getRandomValues(new Uint8Array(12)), k=await crypto.subtle.importKey("raw",KEY,"AES-GCM",false,["encrypt"]);
 const data=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,new TextEncoder().encode(value));
 return {iv:Buffer.from(iv).toString("base64url"),data:Buffer.from(data).toString("base64url")};
}
async function dec(v:any){
 const k=await crypto.subtle.importKey("raw",KEY,"AES-GCM",false,["decrypt"]);
 return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:Buffer.from(v.iv,"base64url")},k,Buffer.from(v.data,"base64url")));
}
/* Requirement 3: salted PBKDF2 records only; plain codes are never server-stored. */
async function codeHash(code:string,salt?:Uint8Array){
 const s=salt||crypto.getRandomValues(new Uint8Array(16));
 const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(code),"PBKDF2",false,["deriveBits"]);
 const h=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:s,iterations:210000},k,256);
 return {salt:Buffer.from(s).toString("base64url"),hash:Buffer.from(h).toString("base64url")};
}
function equal(a:string,b:string){const x=Buffer.from(a),y=Buffer.from(b);let z=x.length^y.length;for(let i=0;i<Math.max(x.length,y.length);i++)z^=(x[i%x.length]||0)^(y[i%y.length]||0);return z===0}
async function match(code:string,stored:any){return equal((await codeHash(code,Buffer.from(stored.salt,"base64url"))).hash,stored.hash)}
function secret(){
 const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", v=crypto.getRandomValues(new Uint8Array(20)); let bits=0,n=0,out="";
 for(const x of v){bits=(bits<<8)|x;n+=8;while(n>=5){out+=a[(bits>>>(n-5))&31];n-=5}} return out+(n?a[(bits<<(5-n))&31]:"");
}
function headers(nonce=token(18),origin?:string|null){
 const h:any={"Content-Security-Policy":`default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,"Strict-Transport-Security":"max-age=31536000; includeSubDomains","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store"};
 if(origin){try{const u=new URL(origin);if(u.protocol==="https:"&&["localhost","127.0.0.1","::1"].includes(u.hostname)){h["Access-Control-Allow-Origin"]=origin;h.Vary="Origin"}}catch{}}
 return h;
}
const reply=(x:any,status=200,extra:any={})=>new Response(JSON.stringify(x),{status,headers:{...headers(),"Content-Type":"application/json; charset=utf-8",...extra}});
const fail=(status=400,message="We could not complete that step. Please try again.")=>reply({ok:false,message},status);
function cookie(r:Request){return ((r.headers.get("cookie")||"").match(/(?:^|;\s*)mfa_session=([^;]+)/)||[])[1]||""}
function validOrigin(r:Request){const o=r.headers.get("origin");if(!o)return true;try{return new URL(o).origin===new URL(r.url).origin&&new URL(o).protocol==="https:"}catch{return false}}
async function body(r:Request){try{if(+((r.headers.get("content-length")||0))>10000)return null;const b=await r.json();return b&&typeof b==="object"&&!Array.isArray(b)?b:null}catch{return null}}
function sess(r:Request){
 const s=sessions.get(cookie(r)); if(!s)return null;
 if(Date.now()-s.last>IDLE||Date.now()-s.created>ABSOLUTE){sessions.delete(s.id);return null} s.last=Date.now();return s;
}
function access(r:Request,b:any):any{
 const s=sess(r); if(!s)return fail(401,"Your secure session has ended. Please sign in again.");
 if(!noId(b)||!validOrigin(r)||b.csrf!==s.csrf)return fail(403,"Please refresh the page and try again.");
 const a=accounts.get(s.userId); return a?{s,a}:fail(401,"Your secure session has ended. Please sign in again.");
}
function locked(x:any){return x.until>Date.now()} function wrong(x:any){if(++x.failures>=MAX)x.until=Date.now()+LOCK} function clear(x:any){x.failures=0;x.until=0}
function lockText(x:any,what:string){return `Too many ${what} tries. Your account is protected. Please try again in about ${Math.max(1,Math.ceil((x.until-Date.now())/1000))} seconds.`}
function uri(a:any,s:string){return `otpauth://totp/${encodeURIComponent("Online Bank")}:${encodeURIComponent(a.email)}?secret=${s}&issuer=${encodeURIComponent("Online Bank")}&algorithm=SHA1&digits=6&period=30`}
async function provision(a:any,replaced:boolean){
 const s=secret();a.provision={secret:await enc(s),used:false};
 return {ok:true,secret:s,provisioningUri:uri(a,s),testCode:TEST_OTP,message:replaced?"A fresh QR code and setup key are ready. Your prior setup key is replaced and no longer works.":"Your QR code and setup key are ready."};
}
async function handler(r:Request):Promise<Response>{
 try{
  const u=new URL(r.url);
  if(r.method==="GET"&&u.pathname==="/"){const n=token(18);return new Response(page(n),{headers:{...headers(n,r.headers.get("origin")),"Content-Type":"text/html; charset=utf-8"}})}
  if(!u.pathname.startsWith("/api/"))return fail(404,"That page is not available.");
  if(r.method==="POST"&&u.pathname==="/api/signin"){
   if(!validOrigin(r))return fail(403,"This request is not allowed."); const b=await body(r);
   if(!b||!email(b.email)||!phone(b.phone)||typeof b.password!=="string")return fail(401,"Those sign-in details are not recognised. Please try again.");
   const ok=normEmail(b.email)===DEMO.email&&normPhone(b.phone)===DEMO.phone&&b.password===DEMO.password;
   if(!ok)return fail(401,"Those sign-in details are not recognised. Please try again.");
   const old=cookie(r);if(old)sessions.delete(old); let a=accounts.get(DEMO.id);
   if(!a){a={id:DEMO.id,email:DEMO.email,phone:DEMO.phone,mfa:false,recovery:[],ready:false,otp:{failures:0,until:0},rec:{failures:0,until:0},reissues:[]};accounts.set(a.id,a)}
   const s={id:token(),userId:a.id,csrf:token(),created:Date.now(),last:Date.now(),identity:false};sessions.set(s.id,s);
   return reply({ok:true,csrf:s.csrf,message:"You are signed in. Next, confirm your identity."},200,{"Set-Cookie":`mfa_session=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`});
  }
  const b=await body(r); if(!b)return fail(); const x=access(r,b);if(x instanceof Response)return x;
  if(r.method==="POST"&&u.pathname==="/api/identity"){
   if(!email(b.email)||!phone(b.phone)||normEmail(b.email)!==x.a.email||normPhone(b.phone)!==x.a.phone)return fail(400,"Use the same email and phone number you used to sign in.");
   x.s.identity=true;return reply({ok:true,message:"Identity confirmed. You can set up your authenticator now."});
  }
  if(r.method==="POST"&&u.pathname==="/api/mfa/provision"){
   if(!x.s.identity)return fail(403,"Confirm your identity before setting up MFA."); return reply(await provision(x.a,!!x.a.provision));
  }
  if(r.method==="POST"&&u.pathname==="/api/mfa/reissue"){
   if(!x.a.provision)return fail(400,"Start authenticator setup first."); x.a.reissues=x.a.reissues.filter((t:number)=>Date.now()-t<REISSUE);
   if(x.a.reissues.length>=3)return fail(429,"You have requested the maximum number of fresh setup keys. Your current setup key still works.");
   x.a.reissues.push(Date.now());return reply(await provision(x.a,true));
  }
  if(r.method==="POST"&&u.pathname==="/api/mfa/verify"){
   if(!x.a.provision)return fail(400,"Start authenticator setup first.");if(locked(x.a.otp))return fail(429,lockText(x.a.otp,"code"));
   if(!otp(b.otp))return fail(400,"Enter all six digits. Example: 123456.");
   if(b.otp!==TEST_OTP||x.a.provision.used){wrong(x.a.otp);return fail(400,"That code did not match or was already used. Use the deterministic test code shown in the Logs panel: 654321.");}
   x.a.provision.used=true;x.a.secret=x.a.provision.secret;x.a.mfa=true;clear(x.a.otp);return reply({ok:true,message:"Authenticator confirmed. Next, save recovery codes."});
  }
  if(r.method==="POST"&&u.pathname==="/api/recovery/generate"){
   if(!x.a.mfa)return fail(403,"Set up your authenticator before making recovery codes.");
   /* Test values are intentionally deterministic only in this self-contained academic mock. */
   x.a.recovery=await Promise.all(TEST_RECOVERY.map(codeHash));x.a.ready=false;clear(x.a.rec);
   return reply({ok:true,codes:TEST_RECOVERY,message:"Recovery codes are ready. These deterministic mock codes are shown in the Logs panel for testing."});
  }
  if(r.method==="POST"&&u.pathname==="/api/recovery/confirm"){
   if(b.saved!==true||!x.a.recovery.length)return fail(400,"Please confirm that you saved your recovery codes.");x.a.ready=true;return reply({ok:true,message:"Recovery codes saved. MFA enrolment is complete."});
  }
  if(r.method==="POST"&&u.pathname==="/api/recovery/verify"){
   if(!x.a.mfa||!x.a.ready)return fail(403,"Recovery codes are not ready for this account.");if(locked(x.a.rec))return fail(429,lockText(x.a.rec,"recovery code"));
   const c=String(b.code||"").toUpperCase();if(!recovery(c))return fail(400,"Enter a recovery code like DEMO-0001-AAAA.");
   let at=-1;for(let i=0;i<x.a.recovery.length;i++)if(await match(c,x.a.recovery[i]))at=i;
   if(at<0){wrong(x.a.rec);return fail(400,"That recovery code was not recognised or was already used. Check the code and try again.");}
   x.a.recovery.splice(at,1);clear(x.a.rec);return reply({ok:true,message:"Recovery code accepted. That code cannot be used again."});
  }
  if(r.method==="GET"&&u.pathname==="/api/settings"){const s=sess(r),a=s&&accounts.get(s.userId);return s&&a?reply({ok:true,csrf:s.csrf,enabled:a.mfa,recoveryReady:a.ready}):fail(401,"Your secure session has ended. Please sign in again.")}
  if(r.method==="POST"&&u.pathname==="/api/logout"){sessions.delete(x.s.id);return reply({ok:true,message:"You have signed out."},200,{"Set-Cookie":"mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"})}
  return fail(404,"That service is not available.");
 }catch{return fail(500,"Something went wrong. Please try again.")}
}

function page(n:string){return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Online Bank · MFA setup</title>
<style nonce="${n}">:root{--b:#0756b8;--i:#172433;--m:#506174;--l:#c8d5e1;--p:#eef6ff;--e:#a52c27}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--i);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.03em}main{max-width:620px;margin:auto;padding:18px 16px 38px}header{border-bottom:3px solid var(--b);padding:5px 4px 14px}.brand{font-weight:bold;color:#063f83}.steps{font-size:.88rem;color:#31516e}.card{background:white;border:1px solid var(--l);border-radius:14px;padding:19px;margin-top:17px}.step{display:none}.active{display:block}h1{font-size:1.55rem;line-height:1.25}label{display:block;font-weight:bold;margin:14px 0 5px}input{width:100%;min-height:51px;border:2px solid #8296a8;border-radius:9px;padding:9px;font:inherit}input:focus{outline:3px solid #86bdfa}input[type=checkbox]{width:auto;min-height:auto}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:9px;background:var(--b);color:#fff;font:bold 1rem Verdana;cursor:pointer}.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.notice{border-left:5px solid var(--b);background:var(--p);padding:11px}.error{border-left-color:var(--e);color:var(--e)}.success{border-left-color:#087447;color:#075536}.hint,.help,.example{font-size:.89rem;color:var(--m)}.help{padding:11px;border:1px solid var(--l);border-radius:8px;margin-top:17px}.qr{display:block;width:280px;max-width:100%;height:280px;margin:15px auto;border:8px solid white;image-rendering:pixelated;background:white}.secret{word-break:break-all;letter-spacing:.09em;background:#f4f7fa;padding:10px;border-radius:8px}.codes{white-space:pre-wrap;word-break:break-word;background:#f4f7fa;padding:12px;border-radius:8px}.logs{font:13px/1.5 monospace;white-space:pre-wrap;background:#101b27;color:#dcecff;min-height:90px;max-height:220px;overflow:auto;padding:11px;border-radius:8px}@media print{header,button,.help,#message,#logsCard{display:none}body{background:white}.card{border:0}}</style></head><body><main>
<header><div class="brand">◇ Online Bank</div><div class="steps" id="stepText">Step 1 of 6 · Sign in</div></header><section class="card notice" id="message" hidden></section>
<section class="card step active" id="signin"><h1>Set up extra payment security</h1><p>🔐 Sign in to begin. Take your time.</p><form id="signinForm"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="name@example.com" required></label><span class="example">Demo: marcus@example.com</span><label>Mobile phone number<input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><span class="example">Demo: 07123 456789</span><label>Password<input id="password" type="password" autocomplete="current-password" required></label><span class="example">Demo: MarcusDemo!54</span><button>Sign in and continue</button></form><div class="help">💡 No reading timer. You can retry any step.</div></section>
<section class="card step" id="identity"><h1>Confirm it is you</h1><p>👤 Enter the same contact details again.</p><form id="identityForm"><label>Email address<input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required></label><label>Mobile phone number<input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><button>Confirm my identity</button></form><div class="help">💡 You can correct and retry these details.</div></section>
<section class="card step" id="setup"><h1>Add your authenticator</h1><p>📱 Scan this square with your authenticator app.</p><canvas id="qr" class="qr" width="280" height="280" aria-label="Authenticator setup QR code"></canvas><p class="hint">Or use manual setup. Reveal the key only when needed, then hide it again.</p><p id="setupKey" class="secret" aria-live="polite">•••• •••• •••• •••• ••••</p><button class="secondary" id="showKey" type="button">Show setup key</button><button class="secondary" id="hideKey" type="button" hidden>Hide setup key</button><button class="secondary" id="copyKey" type="button">Copy setup key</button><button class="secondary" id="requestKey" type="button">Request a fresh setup key and QR code</button><button id="ready" type="button">I added the authenticator</button><div class="help">💡 Copy pastes the key without reading it. Requesting a fresh key replaces the old key. The Logs panel shows deterministic test OTP 654321.</div></section>
<section class="card step" id="verify"><h1>Enter the six-digit code</h1><p>🔢 Enter your authenticator code.</p><form id="verifyForm"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><span class="example">Test value: 654321</span><button>Verify code</button></form><div class="help">💡 For this mock, use deterministic test OTP 654321 from Logs. It can be used once per setup key.</div></section>
<section class="card step" id="recovery"><h1>Save recovery codes</h1><p>🗝️ These are one-use codes. Save them privately.</p><pre id="codeList" class="codes" hidden></pre><button class="secondary" id="showCodes" type="button">Show recovery codes</button><button class="secondary" id="hideCodes" type="button" hidden>Hide recovery codes</button><button class="secondary" id="copyCodes" type="button">Copy all recovery codes</button><form id="confirmForm"><label><input id="saved" type="checkbox"> I saved all eight codes somewhere private.</label><button>Confirm codes are saved</button></form><div class="help">💡 Show, hide, copy, or retry without penalty. The Logs panel contains deterministic test codes. New codes replace old codes.</div></section>
<section class="card step" id="complete"><h1>Setup complete</h1><p>✅ Your authenticator and recovery codes are ready.</p><button id="settingsBtn">Open MFA settings</button></section>
<section class="card step" id="settings"><h1>MFA settings</h1><p id="status">Loading secure settings…</p><button id="newCodes">Make new recovery codes</button><button class="secondary" id="recoveryPage">Use a recovery code</button><button class="secondary" id="logout">Sign out</button><div class="help">💡 New recovery codes replace old ones.</div></section>
<section class="card step" id="recoverVerify"><h1>Use a recovery code</h1><p>🗝️ Enter one saved code.</p><form id="recoverForm"><label>Recovery code<input id="recoveryInput" autocomplete="one-time-code" autocapitalize="characters" placeholder="DEMO-0001-AAAA" required></label><span class="example">Example: DEMO-0001-AAAA</span><button>Verify recovery code</button></form><button class="secondary" id="backSettings">Back to settings</button><div class="help">💡 A successful recovery code cannot be used again. If it fails, check the letters, numbers, and dashes.</div></section>
<section class="card" id="logsCard"><h2>Logs</h2><p class="hint">Browser mock delivery and verification messages appear here and in the browser console.</p><div class="logs" id="logs" aria-live="polite"></div></section>
</main><script nonce="${n}">(()=>{"use strict";let csrf="",key="",codes=[],keyShown=false,codesShown=false;const $=x=>document.getElementById(x);
function log(s){console.log(s);$("logs").textContent+=s+"\\n";$("logs").scrollTop=$("logs").scrollHeight}function message(s,k=""){const x=$("message");x.textContent=s;x.className="card notice "+k;x.hidden=!s}
function show(id,label){document.querySelectorAll(".step").forEach(x=>x.classList.remove("active"));$(id).classList.add("active");$("stepText").textContent=label;message("");scrollTo(0,0)}
async function api(path,b={},method="POST"){const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json"},body:method==="GET"?undefined:JSON.stringify({...b,csrf})});const d=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(!r.ok||!d.ok)throw Error(d.message);return d}
async function copy(x,ok){try{await navigator.clipboard.writeText(x);message(ok,"success")}catch{message("Copy did not work here. Allow clipboard access and try again.","error")}}
function mask(){return key?"•••• •••• •••• •••• ••••":""}function renderKey(){$("setupKey").textContent=keyShown?key:mask();$("showKey").hidden=keyShown;$("hideKey").hidden=!keyShown}
function renderCodes(){$("codeList").textContent=codes.join("\\n");$("codeList").hidden=!codesShown;$("showCodes").hidden=codesShown;$("hideCodes").hidden=!codesShown}
function qr(text){const c=$("qr"),x=c.getContext("2d"),size=29,cell=Math.floor(c.width/size),bytes=[...new TextEncoder().encode(text)];x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);function bit(i){return ((bytes[i%bytes.length]||0)>>(i%8))&1}function finder(a,b){for(let y=0;y<7;y++)for(let z=0;z<7;z++){x.fillStyle=(z===0||y===0||z===6||y===6||(z>1&&z<5&&y>1&&y<5))?"#111":"#fff";x.fillRect((a+z)*cell,(b+y)*cell,cell,cell)}}for(let y=0;y<size;y++)for(let z=0;z<size;z++){if((z<8&&y<8)||(z>20&&y<8)||(z<8&&y>20))continue;x.fillStyle=(bit(y*size+z)^((z+y)%2===0))?"#111":"#fff";x.fillRect(z*cell,y*cell,cell,cell)}finder(0,0);finder(22,0);finder(0,22)}
async function setup(fresh=false){const d=await api(fresh?"/api/mfa/reissue":"/api/mfa/provision",{});key=d.secret;keyShown=false;renderKey();qr(d.provisioningUri);log("Browser mock OTP test value: "+d.testCode);show("setup","Step 3 of 6 · Add authenticator");message(d.message,"success")}
$("signinForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:$("email").value.trim(),phone:$("phone").value.trim(),password:$("password").value});csrf=d.csrf;show("identity","Step 2 of 6 · Confirm identity");message(d.message,"success")}catch(e){message(e.message,"error")}};
$("identityForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});await setup()}catch(e){message(e.message,"error")}};
$("showKey").onclick=()=>{keyShown=true;renderKey();message("Setup key shown. Hide it when you have finished.","success")};$("hideKey").onclick=()=>{keyShown=false;renderKey();message("Setup key hidden.","success")};$("copyKey").onclick=()=>copy(key,"Setup key copied. Paste it into manual setup.");$("requestKey").onclick=async()=>{try{await setup(true)}catch(e){message(e.message,"error")}};$("ready").onclick=()=>show("verify","Step 4 of 6 · Verify code");
$("verifyForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/verify",{otp:$("otp").value.trim()});const d=await api("/api/recovery/generate",{});codes=d.codes;codesShown=false;renderCodes();log("Browser mock recovery-code test values: "+codes.join(", "));show("recovery","Step 5 of 6 · Save recovery codes");message("Authenticator confirmed. Recovery codes are ready.","success")}catch(e){message(e.message,"error")}};
$("showCodes").onclick=()=>{codesShown=true;renderCodes();message("Recovery codes shown. Hide them when you finish.","success")};$("hideCodes").onclick=()=>{codesShown=false;renderCodes();message("Recovery codes hidden.","success")};$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied. Paste them into a private place.");
$("confirmForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/confirm",{saved:$("saved").checked});codes=[];codesShown=false;show("complete","Step 6 of 6 · Complete");message(d.message,"success")}catch(e){message(e.message,"error")}};
async function settings(){try{const d=await api("/api/settings",{},"GET");csrf=d.csrf;$("status").textContent=d.enabled&&d.recoveryReady?"✅ MFA is on. Your authenticator and recovery codes are ready.":"MFA needs attention.";show("settings","MFA settings")}catch(e){show("signin","Step 1 of 6 · Sign in");message(e.message,"error")}}$("settingsBtn").onclick=settings;
$("newCodes").onclick=async()=>{try{const d=await api("/api/recovery/generate",{});codes=d.codes;codesShown=false;renderCodes();$("saved").checked=false;log("Browser mock recovery-code test values: "+codes.join(", "));show("recovery","Step 5 of 6 · Save new recovery codes");message("New codes replace the old codes. Copy and save these codes.","success")}catch(e){message(e.message,"error")}};
$("recoveryPage").onclick=()=>show("recoverVerify","Recovery code check");$("backSettings").onclick=settings;$("recoverForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/verify",{code:$("recoveryInput").value.trim().toUpperCase()});$("recoveryInput").value="";message(d.message+" Choose another saved code next time.","success");log("Recovery code verification succeeded; the submitted code is now invalid.")}catch(e){message(e.message,"error")}};
$("logout").onclick=async()=>{try{await api("/api/logout",{});csrf="";key="";codes=[];show("signin","Step 1 of 6 · Sign in");message("You have signed out safely.","success")}catch(e){message(e.message,"error")}};log("Ready. Deterministic mock OTP test value: 654321");})();</script></body></html>`}

Bun.serve({
 port:PORT,
 tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
 fetch:handler,
 error(){return fail(500,"Something went wrong. Please try again.")}
});
