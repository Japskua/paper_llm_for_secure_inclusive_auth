
import { readFileSync } from "fs";

/* MFA requirements 1–5: owner-bound sessions, CSRF, TLS, secure headers,
   encrypted TOTP material, hashed recovery codes, input validation and limits. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const loginCsrf = new Map<string, number>();
const key = crypto.getRandomValues(new Uint8Array(32));
const enc = new TextEncoder(), dec = new TextDecoder();
const b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", recChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const trusted = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const TEST_MODE_AVAILABLE = process.env.MFA_TEST_MODE === "true" && process.env.NODE_ENV !== "production";
const IDLE = 30 * 60_000, MAX = 8 * 60 * 60_000, LIFE = 15 * 60_000, LOCK = 10 * 60_000, STEP = 30_000;
const EMAIL_MAX = 254, PASSWORD_MAX = 128, OTP_MAX = 6, RECOVERY_MAX = 11;

type Challenge = { h:string; expires:number; used:boolean; fails:number; locked:number };
type Secret = { iv:string; data:string };
type Account = {
  id:string; email:string; identity?:Challenge; secret?:Secret; mfa:boolean;
  authFails:number; authLocked:number; usedSteps:Set<number>;
  recoveries:{salt:string; hash:string; used:boolean}[]; recoveryFails:number; recoveryLocked:number;
};
type Session = { id:string; account:string; csrf:string; created:number; seen:number; verified:boolean };

const marcus:Account = {
  id:"acct_marcus_demo", email:"marcus@example.com", mfa:false, authFails:0, authLocked:0,
  usedSteps:new Set(), recoveries:[], recoveryFails:0, recoveryLocked:0
};
accounts.set(marcus.id, marcus);

const rand=(n=32)=>Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const hash=(s:string)=>new Bun.CryptoHasher("sha256").update(s).digest("hex");
const same=(a:string,b:string)=>{if(a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0};
const clean=(d:any)=>d&&typeof d==="object"&&!Array.isArray(d)&&!["userId","accountId","emailId","redirect","next"].some(k=>k in d);
const emailValid=(v:any)=>typeof v==="string"&&v.length>2&&v.length<=EMAIL_MAX&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const passwordValid=(v:any)=>typeof v==="string"&&v.length>0&&v.length<=PASSWORD_MAX;
const six=(x:any)=>typeof x==="string"&&x.length===OTP_MAX&&/^\d{6}$/.test(x);
const recoveryValid=(x:any)=>typeof x==="string"&&x.length===RECOVERY_MAX&&/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(x);
const testing=(req:Request)=>TEST_MODE_AVAILABLE&&req.headers.get("x-test-mode")==="enabled";
const seed=()=>[...crypto.getRandomValues(new Uint8Array(32))].map(x=>b32[x&31]).join("");
const grouped=(s:string)=>s.match(/.{1,4}/g)!.join("-");
const recovery=()=>{const s=[...crypto.getRandomValues(new Uint8Array(10))].map(x=>recChars[x&31]).join("");return s.slice(0,5)+"-"+s.slice(5)};
const challenge=(code:string):Challenge=>{const salt=rand(24);return {h:salt+":"+hash(salt+code),expires:Date.now()+LIFE,used:false,fails:0,locked:0}};
const identityCode=(id:string)=>String(parseInt(hash("identity-demo|"+id).slice(0,12),16)%1000000).padStart(6,"0");

function check(c:Challenge|undefined,code:string) {
  if(!c)return "Request a new code, then try again.";
  if(c.used)return "That code was already used. Request a new code.";
  if(Date.now()>c.expires)return "That code has expired. Request a new code.";
  if(Date.now()<c.locked)return "Too many attempts. Please wait a few minutes, then request a new code.";
  const [salt,h]=c.h.split(":");
  if(!same(hash(salt+code),h)) {
    if(++c.fails>=5){c.fails=0;c.locked=Date.now()+LOCK;return "Too many attempts. Please wait a few minutes before trying again."}
    return "That code does not match. Check the six digits, or request a new code.";
  }
  c.used=true; return "";
}
async function encrypt(v:string):Promise<Secret>{
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await crypto.subtle.importKey("raw",key,"AES-GCM",false,["encrypt"]);
  const d=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,enc.encode(v));
  return {iv:Buffer.from(iv).toString("base64url"),data:Buffer.from(d).toString("base64url")};
}
async function decrypt(v:Secret){
  const k=await crypto.subtle.importKey("raw",key,"AES-GCM",false,["decrypt"]);
  const d=await crypto.subtle.decrypt({name:"AES-GCM",iv:Buffer.from(v.iv,"base64url")},k,Buffer.from(v.data,"base64url"));
  return dec.decode(d);
}
function decode32(s:string){let out:number[]=[],bits=0,n=0;for(const c of s){const x=b32.indexOf(c);bits=(bits<<5)|x;n+=5;if(n>=8){out.push(bits>>>(n-8)&255);n-=8}}return new Uint8Array(out)}
async function totp(secret:string,step:number){
  const c=new Uint8Array(8);let n=BigInt(step);
  for(let i=7;i>=0;i--){c[i]=Number(n&255n);n>>=8n}
  const k=await crypto.subtle.importKey("raw",decode32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const h=new Uint8Array(await crypto.subtle.sign("HMAC",k,c)),o=h[19]&15;
  const v=((h[o]&127)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3];
  return String(v%1000000).padStart(6,"0");
}

function nonceHeaders(n:string){return {
  "Content-Security-Policy":`default-src 'self'; script-src 'nonce-${n}'; style-src 'nonce-${n}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
  "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer",
  "Cache-Control":"no-store","Vary":"Origin"
}}
function json(x:any,status=200,n=""){return Response.json(x,{status,headers:nonceHeaders(n)})}
function bad(message="We could not complete that request. Please try again.",status=400,n=""){return json({ok:false,message},status,n)}
function cookie(req:Request){return Object.fromEntries((req.headers.get("cookie")||"").split(";").map(x=>{const i=x.indexOf("=");return i<0?["",""]:[x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1))]}))}
function sessionCookie(v:string,age?:number){return `mfa_session=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict${age===undefined?"":`; Max-Age=${age}`}`}
function bootstrapCookie(v:string,age=600){return `signin_csrf=${encodeURIComponent(v)}; Path=/; Secure; SameSite=Strict; Max-Age=${age}`}
function getSession(req:Request){
  const s=sessions.get(cookie(req).mfa_session||""); if(!s)return null;
  if(Date.now()-s.seen>IDLE||Date.now()-s.created>MAX){sessions.delete(s.id);return null}
  s.seen=Date.now(); return s;
}
function owner(req:Request,n:string){const s=getSession(req),a=s&&accounts.get(s.account);return s&&a?{s,a}:{error:bad("Please sign in again to continue.",401,n)}}
function csrf(req:Request,s:Session,n:string){return same(req.headers.get("x-csrf-token")||"",s.csrf)?null:bad("Your secure page has changed. Refresh the page and try again.",403,n)}
async function data(req:Request){const d=await req.json().catch(()=>null);return clean(d)?d:null}

async function api(req:Request,path:string,n:string):Promise<Response>{
  if(path==="/api/csrf-bootstrap"&&req.method==="GET"){
    const token=rand(); loginCsrf.set(token,Date.now()+10*60_000);
    const r=json({ok:true,csrf:token,testModeAvailable:TEST_MODE_AVAILABLE},200,n);
    r.headers.set("Set-Cookie",bootstrapCookie(token)); return r;
  }

  /* Requirement: login CSRF uses an unauthenticated bootstrap token plus trusted Origin. */
  if(path==="/api/signin"&&req.method==="POST"){
    const d=await data(req), origin=req.headers.get("origin")||"", token=req.headers.get("x-login-csrf")||"", stored=cookie(req).signin_csrf||"";
    const validBootstrap=loginCsrf.get(token);
    loginCsrf.delete(token);
    if(!trusted.has(origin)||!validBootstrap||validBootstrap<Date.now()||!same(token,stored))
      return bad("Please refresh the sign-in page and try again.",403,n);
    if(!d||!emailValid(d.email)||!passwordValid(d.password))
      return bad("Enter a valid email address and a password of 128 characters or fewer.",400,n);
    if(!same(d.email.toLowerCase(),marcus.email)||!same(d.password,"MarcusDemo!2025"))
      return bad("We could not sign you in. Check your email and password, then try again.",401,n);
    for(const [id,s] of sessions)if(s.account===marcus.id)sessions.delete(id);
    const s:Session={id:rand(),account:marcus.id,csrf:rand(),created:Date.now(),seen:Date.now(),verified:false};
    sessions.set(s.id,s);
    const r=json({ok:true,next:"#identity"},200,n); r.headers.set("Set-Cookie",sessionCookie(s.id)); return r;
  }

  const o=owner(req,n); if("error" in o)return o.error; const {s,a}=o;
  if(path==="/api/session"&&req.method==="GET")return json({ok:true,csrf:s.csrf,identityVerified:s.verified,mfaEnabled:a.mfa,provisioned:!!a.secret,recoveryCount:a.recoveries.length,testModeAvailable:TEST_MODE_AVAILABLE},200,n);
  if(path==="/api/logout"&&req.method==="POST"){const x=csrf(req,s,n);if(x)return x;sessions.delete(s.id);const r=json({ok:true},200,n);r.headers.set("Set-Cookie",sessionCookie("",0));return r}

  const d=await data(req); if(req.method==="POST"&&!d)return bad(undefined,400,n);
  if(req.method==="POST"){const x=csrf(req,s,n);if(x)return x}

  if(path==="/api/identity/request"&&req.method==="POST"){
    const code=identityCode(s.id); a.identity=challenge(code);
    return json({ok:true,...(testing(req)?{testValue:code}:{})},200,n);
  }
  if(path==="/api/identity/verify"&&req.method==="POST"){
    if(!six(d.code))return bad("Enter exactly six digits, for example 123456.",400,n);
    const m=check(a.identity,d.code); if(m)return bad(m,400,n);
    s.verified=true; return json({ok:true,next:a.mfa?"#settings":"#setup"},200,n);
  }
  if(!s.verified)return bad("Please complete the identity check before changing MFA settings.",403,n);

  if(path==="/api/authenticator/provision"&&req.method==="POST"){
    const v=seed(); a.secret=await encrypt(v); a.authFails=0; a.authLocked=0; a.usedSteps.clear();
    const uri=`otpauth://totp/Local%20Bank:${encodeURIComponent(a.email)}?secret=${v}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    const result:any={ok:true,secret:grouped(v),uri};
    if(testing(req))result.testValue=await totp(v,Math.floor(Date.now()/STEP));
    return json(result,200,n);
  }
  if(path==="/api/authenticator/confirm"&&req.method==="POST"){
    if(!six(d.code))return bad("Enter exactly six digits, for example 123456.",400,n);
    if(!a.secret)return bad("Show a setup code before confirming your authenticator.",400,n);
    if(Date.now()<a.authLocked)return bad("Too many attempts. Please wait a few minutes, then try again.",429,n);
    const v=await decrypt(a.secret),now=Math.floor(Date.now()/STEP);let found=-1;
    for(const q of[now-1,now,now+1])if(same(await totp(v,q),d.code)){found=q;break}
    if(found<0||a.usedSteps.has(found)){
      if(++a.authFails>=5){a.authFails=0;a.authLocked=Date.now()+LOCK;return bad("Too many attempts. Please wait a few minutes before trying again.",429,n)}
      return bad(found>=0?"That authenticator code was already used. Wait for a new code, then try again.":"That code does not match your authenticator. Check the six digits and try again.",400,n);
    }
    a.usedSteps.add(found);a.authFails=0;a.mfa=true;return json({ok:true,next:"#recovery"},200,n);
  }
  if(path==="/api/recovery/generate"&&req.method==="POST"){
    if(!a.mfa)return bad("Connect your authenticator before creating recovery codes.",403,n);
    const codes=Array.from({length:8},recovery);
    a.recoveries=codes.map(c=>{const salt=rand(24);return {salt,hash:hash(salt+c),used:false}});
    return json({ok:true,codes},200,n);
  }
  if(path==="/api/recovery/use"&&req.method==="POST"){
    if(!recoveryValid(d.code))return bad("Enter a recovery code like ABCDE-23456.",400,n);
    if(Date.now()<a.recoveryLocked)return bad("Too many attempts. Please wait a few minutes, then try another code.",429,n);
    const found=a.recoveries.find(x=>!x.used&&same(x.hash,hash(x.salt+d.code)));
    if(!found){
      if(++a.recoveryFails>=5){a.recoveryFails=0;a.recoveryLocked=Date.now()+LOCK;return bad("Too many attempts. Please wait a few minutes before trying again.",429,n)}
      return bad("That recovery code is not available. Check it, or use another unused code.",400,n);
    }
    found.used=true;a.recoveryFails=0;return json({ok:true,message:"Recovery code accepted. It cannot be used again."},200,n);
  }
  if(path==="/api/settings"&&req.method==="GET")return json({ok:true,email:a.email,remaining:a.recoveries.filter(x=>!x.used).length},200,n);
  return bad("That page is not available.",404,n);
}

const page=(n:string)=>`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank security setup</title>
<style nonce="${n}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}
.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}.brand{font-weight:800;color:#034a7c}
button,input{font:inherit;letter-spacing:inherit}.link{border:0;background:none;color:var(--blue);text-decoration:underline;cursor:pointer;padding:6px}.hide{display:none!important}
.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress .on{background:var(--blue)}
h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}.lead,.example{color:var(--muted)}.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:#eef7fc;border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:#8d2424;color:#702020}
label{display:block;font-weight:800;margin-top:16px}input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}input:focus{outline:3px solid #82c9ee;outline-offset:2px}
.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800;cursor:pointer}.primary{border:0;background:var(--blue);color:#fff}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}
.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhereword;min-height:56px}.qrwrap{display:grid;place-items:center;margin:16px 0}.qr{width:min(76vw,270px);height:min(76vw,270px);image-rendering:pixelated;border:10px solid #fff;box-shadow:0 0 0 2px #d4dfe5}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace;letter-spacing:.06em}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}.small{font-size:.92rem}
@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style></head><body><main class="shell"><header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header>
<nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Activity logs"><h2>🔎 Activity logs</h2><p class="example">General activity is shown here. Private codes are never shown.</p><pre id="logs">Ready.</pre></section>
</main><script nonce="${n}">
(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout");
let csrf="",loginCsrf="",provision=null,codes=[],testAvailable=false,testEnabled=false,notice="";
const routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved","#settings","#use"]);
const help=()=>'<p><button class="link" data-help>Need help?</button></p>';
function attach(){document.querySelectorAll("[data-help]").forEach(b=>b.onclick=()=>alert("Take your time. You can retry safely. Use the example shown beside each box."))}
function log(s){console.log(s);logs.textContent+=(logs.textContent==="Ready."?"\\\\n":"\\\\n")+s}
function go(x){location.hash=routes.has(x)?x:"#signin"}
function prog(x){for(let i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=x)}
function err(s){const e=document.querySelector("#form-error");if(e){e.className="error";e.textContent=s;e.focus()}}
function success(){const x=notice;notice="";return x?'<div class="success">'+x+"</div>":""}
async function api(path,method="GET",body){
 const o={method,headers:{Accept:"application/json"}};
 if(testEnabled)o.headers["X-Test-Mode"]="enabled";
 if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}
 try{const r=await fetch(path,o),j=await r.json();if(r.status===401){csrf="";logout.classList.add("hide")}return j}catch{return {ok:false,message:"We could not connect securely. Please try again."}}
}
async function bootstrap(){const r=await api("/api/csrf-bootstrap");if(r.ok){loginCsrf=r.csrf;testAvailable=!!r.testModeAvailable}return r}
async function signed(){const s=await api("/api/session");if(s.ok){csrf=s.csrf;testAvailable=!!s.testModeAvailable;logout.classList.remove("hide");return s}return null}
function testButton(){return testAvailable?'<button id="test" class="link small">Enable test-only values</button>':""}
function enableTest(){const b=document.querySelector("#test");if(b)b.onclick=()=>{testEnabled=true;log("Test-only values enabled for this browser page.");b.textContent="Test-only values enabled"}}

/* Local QR generator: Version 10-L QR, byte mode, Reed–Solomon ECC. It encodes provision.uri without a network call. */
function qr(uri){
 const N=57,m=Array.from({length:N},()=>Array(N).fill(null)),gf=new Uint8Array(512),lg=new Uint8Array(256);let x=1;
 for(let i=0;i<255;i++){gf[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)gf[i]=gf[i-255];
 const put=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)put(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))?1:0)}
 finder(0,0);finder(0,N-7);finder(N-7,0);
 for(const r of [6,28,50])for(const c of [6,28,50])if(m[r][c]===null){for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)put(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1?1:0)}
 for(let i=8;i<N-8;i++){put(6,i,i%2?0:1);put(i,6,i%2?0:1)}put(N-8,8,1);
 function reserve(r,c){if(m[r][c]===null)m[r][c]=0}
 for(let i=0;i<9;i++){reserve(8,i);reserve(i,8);reserve(8,N-1-i);reserve(N-1-i,8)}for(let i=0;i<18;i++){reserve(i,N-11);reserve(N-11,i)}
 const bits=[];const add=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>i)&1)};const bytes=new TextEncoder().encode(uri);add(4,4);add(bytes.length,16);bytes.forEach(v=>add(v,8));add(0,Math.min(4,274*8-bits.length));while(bits.length%8)bits.push(0);
 const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;raw.length<274;p++)raw.push(p%2?17:236);
 const gen=[1];for(let i=0;i<18;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=gf[lg[gen[j]]+i]}gen.splice(0,gen.length,...next)}
 const blocks=[],sizes=[68,68,69,69];let at=0;
 for(const size of sizes){const d=raw.slice(at,at+=size),r=Array(18).fill(0);for(const q of d){const f=q^r.shift();r.push(0);for(let j=0;j<18;j++)if(gen[j+1])r[j]^=gf[lg[gen[j+1]]+lg[f]]}blocks.push([d,r])}
 const stream=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b[0].length)stream.push(b[0][i]);for(let i=0;i<18;i++)for(const b of blocks)stream.push(b[1][i]);
 const dataBits=[];stream.forEach(v=>addBits(v));function addBits(v){for(let i=7;i>=0;i--)dataBits.push((v>>i)&1)}
 let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){const r=up?N-1-q:q;for(const cc of [c,c-1])if(m[r][cc]===null){let v=dataBits[k++]||0;if((r+cc)%2===0)v^=1;m[r][cc]=v}}up=!up}
 let f=(1<<3)|0;let v=f<<10;while(v.toString(2).length>=11)v^=0x537<<(v.toString(2).length-11);f=((f<<10)|v)^0x5412;
 for(let i=0;i<15;i++){const bit=(f>>i)&1;const a=i<6?[i,8]:i<8?[i+1,8]:[N-15+i,8];const b=i<8?[8,N-i-1]:i<9?[8,15-i]:[8,14-i];put(a[0],a[1],bit);put(b[0],b[1],bit)}
 let vv=10<<12;while(vv.toString(2).length>=13)vv^=0x1f25<<(vv.toString(2).length-13);vv=(10<<12)|vv;
 for(let i=0;i<18;i++){const bit=(vv>>i)&1;put(Math.floor(i/3),N-11+i%3,bit);put(N-11+i%3,Math.floor(i/3),bit)}
 const canvas=document.createElement("canvas");canvas.width=canvas.height=N*5;canvas.className="qr";canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scannable authenticator setup QR code");
 const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(m[r][c])ctx.fillRect(c*5,r*5,5,5);return canvas;
}
function signin(){
 prog(0);app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="f"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" maxlength="254" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" maxlength="128" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+testButton()+help();
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();if(!loginCsrf){const b=await bootstrap();if(!b.ok)return err(b.message)}const f=new FormData(e.target),o={method:"POST",headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},body:JSON.stringify({email:f.get("email"),password:f.get("password")})};if(testEnabled)o.headers["X-Test-Mode"]="enabled";const r=await fetch("/api/signin",o).then(x=>x.json()).catch(()=>({ok:false,message:"We could not connect securely. Please try again."}));if(!r.ok)return err(r.message);log("Sign-in complete. Secure session created.");notice="Signed in successfully. Next: get your identity code.";go(r.next)};enableTest();attach();
}
function identity(){
 prog(1);app.innerHTML='<h1>🪪 Check it is you</h1>'+success()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get" class="primary">Get identity code</button>'+help();
 const request=async()=>{const r=await api("/api/identity/request","POST",{});if(!r.ok)return err(r.message);if(r.testValue)log("Test-only identity value: "+r.testValue);entry()};
 document.querySelector("#get").onclick=request;attach();
 function entry(){app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="f"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return err(r.message);notice="Identity check complete. Next: set up your authenticator.";go(r.next)};document.querySelector("#again").onclick=request;attach()}
}
async function provisionNew(){const r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return err(r.message);provision=r;if(r.testValue)log("Test-only authenticator value: "+r.testValue);showProvision()}
function setup(){prog(2);app.innerHTML='<h1>📱 Set up your authenticator</h1>'+success()+'<p class="lead">Scan a code, or copy a setup key. You do not need to write it down.</p><div id="form-error" tabindex="-1"></div><button id="go" class="primary">Show setup code</button>'+help();document.querySelector("#go").onclick=provisionNew;attach()}
function showProvision(){
 prog(2);app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup code created. Next: scan it or copy the key.</div><p class="lead">Use your authenticator app to scan the square, or copy the setup key.</p><div id="private"></div><button id="toggle" class="secondary">Hide setup values</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new" class="link">Show a new setup code</button>'+help();
 const box=document.querySelector("#private");let shown=true;function draw(){box.innerHTML="";if(shown){const wrap=document.createElement("div");wrap.className="qrwrap";wrap.appendChild(qr(provision.uri));box.appendChild(wrap);const key=document.createElement("div");key.className="secret code";key.textContent=provision.secret;box.appendChild(key)}else box.innerHTML='<div class="hint">Setup values are hidden. Select reveal when you are ready.</div>';document.querySelector("#toggle").textContent=shown?"Hide setup values":"Reveal setup values"}draw();
 document.querySelector("#toggle").onclick=()=>{shown=!shown;draw()};document.querySelector("#copy").onclick=()=>navigator.clipboard.writeText(provision.secret).then(()=>alert("Setup key copied.")).catch(()=>alert("Select the setup key and copy it."));document.querySelector("#next").onclick=()=>go("#confirm");document.querySelector("#new").onclick=provisionNew;attach();
}
function confirm(){prog(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><form id="f"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup code again</button>'+help();document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return err(r.message);log("Authenticator confirmed.");notice="Authenticator confirmed. Next: create your recovery codes.";go(r.next)};document.querySelector("#retry").onclick=()=>provision?showProvision():go("#setup");attach()}
function recovery(){
 prog(4);app.innerHTML='<h1>🧾 Save recovery codes</h1>'+success()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button>'+help();
 document.querySelector("#create").onclick=async()=>{const r=await api("/api/recovery/generate","POST",{});if(!r.ok)return err(r.message);codes=r.codes;showCodes()};attach();
}
function showCodes(){
 app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button>'+help();
 let shown=true;const p=document.querySelector("#private");function draw(){p.innerHTML="";if(shown){const l=document.createElement("ul");l.className="codes";codes.forEach(c=>{const x=document.createElement("li");x.textContent=c;l.appendChild(x)});p.appendChild(l)}else p.innerHTML='<div class="hint">Recovery codes are hidden. Select reveal when you are ready.</div>';document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes"}draw();
 document.querySelector("#toggle").onclick=()=>{shown=!shown;draw()};document.querySelector("#copy").onclick=()=>navigator.clipboard.writeText(codes.join("\\n")).then(()=>alert("Recovery codes copied.")).catch(()=>alert("Select the codes and copy them."));document.querySelector("#done").onclick=()=>go("#saved");attach();
}
async function settings(){prog(4);const r=await api("/api/settings");if(!r.ok)return;app.innerHTML='<h1>⚙️ Security settings</h1><div class="success">MFA is on for <b id="email"></b>.</div><p id="remain"></p><button id="newcodes" class="primary">Create new recovery codes</button><button id="use" class="secondary">Use a recovery code</button>'+help();document.querySelector("#email").textContent=r.email;document.querySelector("#remain").textContent=r.remaining+" unused code(s) remain.";document.querySelector("#newcodes").onclick=()=>go("#recovery");document.querySelector("#use").onclick=()=>go("#use");attach()}
function use(){prog(4);app.innerHTML='<h1>🔑 Use a recovery code</h1><form id="f"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" placeholder="ABCDE-23456" maxlength="11" pattern="[A-Za-z2-9]{5}-[A-Za-z2-9]{5}" required><button class="primary">Use recovery code</button></form>'+help();document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/use","POST",{code:String(new FormData(e.target).get("code")).toUpperCase().trim()});if(!r.ok)return err(r.message);app.innerHTML='<h1>✓ Recovery code accepted</h1><div class="success"></div><button id="back" class="primary">Back to settings</button>'+help();document.querySelector(".success").textContent=r.message;document.querySelector("#back").onclick=()=>go("#settings");attach()};attach()}
function saved(){prog(4);app.innerHTML='<h1>🎉 Security setup complete</h1><div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="go" class="primary">View security settings</button>'+help();document.querySelector("#go").onclick=()=>go("#settings");attach()}
async function render(){const route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin"){await bootstrap();return signin()}const s=await signed();if(!s)return go("#signin");if(!s.identityVerified&&route!=="#identity")return go("#identity");if(!s.mfaEnabled&&!["#identity","#setup","#confirm"].includes(route))return go(s.provisioned?"#confirm":"#setup");if(s.mfaEnabled&&s.recoveryCount===0&&["#settings","#saved","#use"].includes(route))return go("#recovery");({"#identity":identity,"#setup":setup,"#confirm":confirm,"#recovery":recovery,"#saved":saved,"#settings":settings,"#use":use}[route])()}
logout.onclick=async()=>{const r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;codes=[];log("Secure session ended.");go("#signin")}};addEventListener("hashchange",render);render();
})()</script></body></html>`;

const cert=readFileSync("certs/cert.pem"),keyFile=readFileSync("certs/key.pem");
Bun.serve({
  port:3000,tls:{cert,key:keyFile},
  fetch:async req=>{
    const n=rand(18);
    try{
      const u=new URL(req.url),origin=req.headers.get("origin");
      if(req.headers.get("x-forwarded-proto")==="http")return new Response("Secure connection required.",{status:426,headers:nonceHeaders(n)});
      if(origin&&!trusted.has(origin))return new Response("Not allowed.",{status:403,headers:nonceHeaders(n)});
      const cors=origin?{"Access-Control-Allow-Origin":origin}:{};
      if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{...nonceHeaders(n),...cors,"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, X-CSRF-Token, X-Login-CSRF, X-Test-Mode"}});
      if(u.pathname.startsWith("/api/")){const r=await api(req,u.pathname,n);Object.entries(cors).forEach(([k,v])=>r.headers.set(k,v));return r}
      if(req.method==="GET"&&(u.pathname==="/"||u.pathname==="/index.html"))return new Response(page(n),{headers:{...nonceHeaders(n),...cors,"Content-Type":"text/html; charset=utf-8"}});
      return new Response("Page not found.",{status:404,headers:nonceHeaders(n)});
    }catch{return new Response("We could not complete that request. Please try again.",{status:500,headers:nonceHeaders(n)})}
  }
});
