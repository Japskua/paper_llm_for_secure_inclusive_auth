
import { readFileSync } from "fs";

/* Requirements 1–5: owner-bound sessions, CSRF, TLS, secure headers,
   encrypted authenticator secrets, hashed recovery codes, validation and limits. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const loginTokens = new Map<string, number>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const encoder = new TextEncoder(), decoder = new TextDecoder();
const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const recoveryChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const trustedOrigins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const IDLE_TIMEOUT = 30 * 60_000, ABSOLUTE_TIMEOUT = 8 * 60 * 60_000;
const CODE_LIFETIME = 15 * 60_000, LOCK_TIME = 10 * 60_000, TOTP_STEP = 30_000;

type Challenge = { hash:string; expires:number; used:boolean; failures:number; lockedUntil:number };
type EncryptedSecret = { iv:string; data:string };
type Recovery = { salt:string; hash:string; used:boolean };
type Account = {
  id:string; email:string; identity?:Challenge; secret?:EncryptedSecret; mfa:boolean;
  authenticatorFailures:number; authenticatorLockedUntil:number; usedTotpSteps:Set<number>;
  recoveries:Recovery[]; recoveryFailures:number; recoveryLockedUntil:number;
};
type Session = { id:string; accountId:string; csrf:string; created:number; seen:number; identityVerified:boolean };

const marcus: Account = {
  id:"acct_marcus_demo", email:"marcus@example.com", mfa:false,
  authenticatorFailures:0, authenticatorLockedUntil:0, usedTotpSteps:new Set(),
  recoveries:[], recoveryFailures:0, recoveryLockedUntil:0
};
accounts.set(marcus.id, marcus);

const random = (bytes=32) => Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
const sha256 = (value:string) => new Bun.CryptoHasher("sha256").update(value).digest("hex");
function equal(a:string,b:string) {
  if (a.length !== b.length) return false;
  let n=0; for(let i=0;i<a.length;i++) n|=a.charCodeAt(i)^b.charCodeAt(i);
  return n===0;
}
function cleanObject(v:unknown): v is Record<string,unknown> {
  if(!v || typeof v!=="object" || Array.isArray(v)) return false;
  return !["id","userId","accountId","emailId","redirect","next"].some(k=>k in (v as Record<string,unknown>));
}
const validEmail=(v:unknown)=>typeof v==="string"&&v.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPassword=(v:unknown)=>typeof v==="string"&&v.length>0&&v.length<=128;
const validSixDigits=(v:unknown)=>typeof v==="string"&&/^\d{6}$/.test(v);
const validRecoveryCode=(v:unknown)=>typeof v==="string"&&/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v);

function makeSeed(){ return [...crypto.getRandomValues(new Uint8Array(32))].map(x=>base32[x&31]).join(""); }
function groupSeed(v:string){ return v.match(/.{1,4}/g)!.join("-"); }
function makeRecoveryCode() {
  const v=[...crypto.getRandomValues(new Uint8Array(10))].map(x=>recoveryChars[x&31]).join("");
  return v.slice(0,5)+"-"+v.slice(5);
}
function identityCode(sessionId:string) {
  return String(parseInt(sha256("identity-demo|"+sessionId).slice(0,12),16)%1_000_000).padStart(6,"0");
}
function makeChallenge(code:string):Challenge {
  const salt=random(24);
  return {hash:salt+":"+sha256(salt+code),expires:Date.now()+CODE_LIFETIME,used:false,failures:0,lockedUntil:0};
}
function checkChallenge(c:Challenge|undefined, code:string) {
  if(!c) return "Request a new code, then try again.";
  if(c.used) return "That code was already used. Request a new code.";
  if(Date.now()>c.expires) return "That code has expired. Request a new code.";
  if(Date.now()<c.lockedUntil) return "Too many attempts. Please wait a few minutes, then request a new code.";
  const [salt,hash]=c.hash.split(":");
  if(!equal(sha256(salt+code),hash)) {
    if(++c.failures>=5) { c.failures=0;c.lockedUntil=Date.now()+LOCK_TIME;return "Too many attempts. Please wait a few minutes before trying again."; }
    return "That code does not match. Check the six digits, or request a new code.";
  }
  c.used=true; return "";
}
async function encryptSecret(value:string):Promise<EncryptedSecret> {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await crypto.subtle.importKey("raw",encryptionKey,"AES-GCM",false,["encrypt"]);
  const data=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,encoder.encode(value));
  return {iv:Buffer.from(iv).toString("base64url"),data:Buffer.from(data).toString("base64url")};
}
async function decryptSecret(value:EncryptedSecret) {
  const key=await crypto.subtle.importKey("raw",encryptionKey,"AES-GCM",false,["decrypt"]);
  const data=await crypto.subtle.decrypt({name:"AES-GCM",iv:Buffer.from(value.iv,"base64url")},key,Buffer.from(value.data,"base64url"));
  return decoder.decode(data);
}
function decodeBase32(value:string) {
  const out:number[]=[]; let bits=0, buffer=0;
  for(const char of value) {
    buffer=(buffer<<5)|base32.indexOf(char); bits+=5;
    if(bits>=8) {out.push((buffer>>>(bits-8))&255);bits-=8;}
  }
  return new Uint8Array(out);
}
async function totp(secret:string, step:number) {
  const counter=new Uint8Array(8); let value=BigInt(step);
  for(let i=7;i>=0;i--){counter[i]=Number(value&255n);value>>=8n;}
  const key=await crypto.subtle.importKey("raw",decodeBase32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,counter)), off=sig[19]&15;
  const code=((sig[off]&127)<<24)|(sig[off+1]<<16)|(sig[off+2]<<8)|sig[off+3];
  return String(code%1_000_000).padStart(6,"0");
}

/* Requirement 2: strict CSP, HSTS, anti-clickjacking, nosniff, no cache. */
function securityHeaders(nonce:string) {
  return {
    "Content-Security-Policy":"default-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
    "X-Content-Type-Options":"nosniff", "X-Frame-Options":"DENY", "Referrer-Policy":"no-referrer",
    "Cache-Control":"no-store", "Vary":"Origin"
  };
}
function json(data:unknown,status=200,nonce=""){return Response.json(data,{status,headers:securityHeaders(nonce)});}
function failure(message="We could not complete that request. Please try again.",status=400,nonce=""){return json({ok:false,message},status,nonce);}
function cookies(request:Request) {
  return Object.fromEntries((request.headers.get("cookie")||"").split(";").map(p=>{
    const i=p.indexOf("=");return i<0?["",""]:[p.slice(0,i).trim(),decodeURIComponent(p.slice(i+1))];
  }));
}
function sessionCookie(v:string,age?:number){return "mfa_session="+encodeURIComponent(v)+"; Path=/; HttpOnly; Secure; SameSite=Strict"+(age===undefined?"":"; Max-Age="+age);}
function bootstrapCookie(v:string){return "signin_csrf="+encodeURIComponent(v)+"; Path=/; Secure; SameSite=Strict; Max-Age=600";}
function getSession(request:Request) {
  const session=sessions.get(cookies(request).mfa_session||"");
  if(!session)return null;
  if(Date.now()-session.seen>IDLE_TIMEOUT||Date.now()-session.created>ABSOLUTE_TIMEOUT){sessions.delete(session.id);return null;}
  session.seen=Date.now();return session;
}
function getOwner(request:Request,nonce:string) {
  const session=getSession(request), account=session&&accounts.get(session.accountId);
  return session&&account?{session,account}:{error:failure("Please sign in again to continue.",401,nonce)};
}
function csrfValid(request:Request,session:Session,nonce:string) {
  return equal(request.headers.get("x-csrf-token")||"",session.csrf)?null:failure("Your secure page has changed. Refresh the page and try again.",403,nonce);
}
async function requestData(request:Request){const v=await request.json().catch(()=>null);return cleanObject(v)?v:null;}

async function api(request:Request,path:string,nonce:string):Promise<Response> {
  if(path==="/api/csrf-bootstrap"&&request.method==="GET"){
    const token=random();loginTokens.set(token,Date.now()+600_000);
    const r=json({ok:true,csrf:token},200,nonce);r.headers.set("Set-Cookie",bootstrapCookie(token));return r;
  }
  if(path==="/api/signin"&&request.method==="POST"){
    const body=await requestData(request), token=request.headers.get("x-login-csrf")||"", cookie=cookies(request).signin_csrf||"";
    const expires=loginTokens.get(token);loginTokens.delete(token);
    if(!trustedOrigins.has(request.headers.get("origin")||"")||!expires||expires<Date.now()||!equal(token,cookie))return failure("Please refresh the sign-in page and try again.",403,nonce);
    if(!body||!validEmail(body.email)||!validPassword(body.password))return failure("Enter a valid email address and a password of 128 characters or fewer.",400,nonce);
    if(!equal(String(body.email).toLowerCase(),marcus.email)||!equal(String(body.password),"MarcusDemo!2025"))return failure("We could not sign you in. Check your email and password, then try again.",401,nonce);
    for(const [id,s] of sessions)if(s.accountId===marcus.id)sessions.delete(id);
    const session:Session={id:random(),accountId:marcus.id,csrf:random(),created:Date.now(),seen:Date.now(),identityVerified:false};
    sessions.set(session.id,session);const r=json({ok:true,next:"#identity"},200,nonce);r.headers.set("Set-Cookie",sessionCookie(session.id));return r;
  }

  const owner=getOwner(request,nonce);if("error" in owner)return owner.error;
  const {session,account}=owner;
  if(path==="/api/session"&&request.method==="GET")return json({ok:true,csrf:session.csrf,identityVerified:session.identityVerified,mfaEnabled:account.mfa,provisioned:!!account.secret,recoveryCount:account.recoveries.length},200,nonce);
  if(path==="/api/settings"&&request.method==="GET"){
    if(!session.identityVerified||!account.mfa)return failure("Please complete security setup before viewing settings.",403,nonce);
    return json({ok:true,email:account.email,remaining:account.recoveries.filter(x=>!x.used).length},200,nonce);
  }
  if(request.method!=="POST")return failure("That page is not available.",404,nonce);
  const body=await requestData(request);if(!body)return failure(undefined,400,nonce);
  const csrfError=csrfValid(request,session,nonce);if(csrfError)return csrfError;

  if(path==="/api/logout"){sessions.delete(session.id);const r=json({ok:true},200,nonce);r.headers.set("Set-Cookie",sessionCookie("",0));return r;}
  if(path==="/api/identity/request"){
    const code=identityCode(session.id);account.identity=makeChallenge(code);return json({ok:true,simulatedCode:code},200,nonce);
  }
  if(path==="/api/identity/verify"){
    if(!validSixDigits(body.code))return failure("Enter exactly six digits, for example 123456.",400,nonce);
    const message=checkChallenge(account.identity,String(body.code));if(message)return failure(message,400,nonce);
    session.identityVerified=true;return json({ok:true,next:account.mfa?"#settings":"#setup"},200,nonce);
  }
  if(!session.identityVerified)return failure("Please complete the identity check before changing MFA settings.",403,nonce);

  /* Task: authenticated owner-bound provisioning response includes standard encoded otpauth URI. */
  if(path==="/api/authenticator/provision"){
    const secret=makeSeed();account.secret=await encryptSecret(secret);account.authenticatorFailures=0;account.authenticatorLockedUntil=0;account.usedTotpSteps.clear();
    const issuer="Local Bank", label=issuer+":"+account.email;
    const provisioningUri="otpauth://totp/"+encodeURIComponent(label)+"?secret="+encodeURIComponent(secret)+"&issuer="+encodeURIComponent(issuer)+"&algorithm=SHA1&digits=6&period=30";
    return json({ok:true,secret:groupSeed(secret),provisioningUri,simulatedOtp:await totp(secret,Math.floor(Date.now()/TOTP_STEP))},200,nonce);
  }
  if(path==="/api/authenticator/confirm"){
    if(!validSixDigits(body.code))return failure("Enter exactly six digits, for example 123456.",400,nonce);
    if(!account.secret)return failure("Show a setup key before confirming your authenticator.",400,nonce);
    if(Date.now()<account.authenticatorLockedUntil)return failure("Too many attempts. Please wait a few minutes, then try again.",429,nonce);
    const secret=await decryptSecret(account.secret), now=Math.floor(Date.now()/TOTP_STEP);let match=-1;
    for(const step of [now-1,now,now+1])if(equal(await totp(secret,step),String(body.code))){match=step;break;}
    if(match<0||account.usedTotpSteps.has(match)){
      if(++account.authenticatorFailures>=5){account.authenticatorFailures=0;account.authenticatorLockedUntil=Date.now()+LOCK_TIME;return failure("Too many attempts. Please wait a few minutes before trying again.",429,nonce);}
      return failure(match>=0?"That authenticator code was already used. Show a new setup code and try again.":"That code does not match your authenticator. Check the six digits and try again.",400,nonce);
    }
    account.usedTotpSteps.add(match);account.authenticatorFailures=0;account.mfa=true;return json({ok:true,next:"#recovery"},200,nonce);
  }
  if(path==="/api/recovery/generate"){
    if(!account.mfa)return failure("Connect your authenticator before creating recovery codes.",403,nonce);
    const codes=Array.from({length:8},makeRecoveryCode);account.recoveries=codes.map(code=>{const salt=random(24);return {salt,hash:sha256(salt+code),used:false};});
    return json({ok:true,codes},200,nonce);
  }
  if(path==="/api/recovery/use"){
    if(!validRecoveryCode(body.code))return failure("Enter a recovery code like ABCDE-23456.",400,nonce);
    if(Date.now()<account.recoveryLockedUntil)return failure("Too many attempts. Please wait a few minutes, then try another code.",429,nonce);
    const code=String(body.code), found=account.recoveries.find(x=>!x.used&&equal(x.hash,sha256(x.salt+code)));
    if(!found){if(++account.recoveryFailures>=5){account.recoveryFailures=0;account.recoveryLockedUntil=Date.now()+LOCK_TIME;return failure("Too many attempts. Please wait a few minutes before trying again.",429,nonce);}return failure("That recovery code is not available. Check it, or use another unused code.",400,nonce);}
    found.used=true;account.recoveryFailures=0;return json({ok:true,message:"Recovery code accepted. It cannot be used again."},200,nonce);
  }
  return failure("That page is not available.",404,nonce);
}

function page(nonce:string){return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank security setup</title><style nonce="${nonce}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df;--soft:#eef7fc}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}.brand{font-weight:800;color:#034a7c}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:6px}.hide{display:none!important}.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress .on{background:var(--blue)}h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}h2{font-size:1.15rem}.lead,.example{color:var(--muted)}.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:var(--soft);border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:#8d2424;color:#702020}label{display:block;font-weight:800;margin-top:16px}input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}input:focus{outline:3px solid #82c9ee;outline-offset:2px}.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800}.primary{border:0;background:var(--blue);color:#fff}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhere;min-height:56px}.qr-wrap{text-align:center;margin:17px 0;padding:16px;background:#f4f8fa;border-radius:10px}.qr-wrap canvas{width:min(100%,294px);height:auto;image-rendering:pixelated;background:#fff}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace;letter-spacing:.06em}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}.small{font-size:.92rem}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style></head><body><main class="shell"><header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header><nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav><section id="app" aria-live="polite"></section><section class="logs" aria-label="Activity logs"><h2>🔎 Activity logs</h2><p class="example">General activity is shown here. Private codes are never shown.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">
(function(){"use strict";
var app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout"),csrf="",loginCsrf="",provision=null,recoveryCodes=[],notice="",routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved","#settings","#use"]);
function esc(v){var n=document.createElement("span");n.textContent=String(v);return n.innerHTML}function activity(m){console.log(m);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+m}function go(r){location.hash=routes.has(r)?r:"#signin"}function progress(s){for(var i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=s)}function help(){return '<p><button class="link" data-help>Need help?</button></p>'}function attachHelp(){document.querySelectorAll("[data-help]").forEach(function(b){b.onclick=function(){alert("Take your time. You can retry safely. Use the example beside each box.")}})}function showError(m){var b=document.querySelector("#form-error");if(b){b.className="error";b.textContent=m;b.focus()}}function successNotice(){var n=notice;notice="";return n?'<div class="success">'+esc(n)+"</div>":""}
async function api(path,method,body){method=method||"GET";var o={method:method,headers:{Accept:"application/json"}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}try{var r=await fetch(path,o),d=await r.json();if(r.status===401){csrf="";logout.classList.add("hide")}return d}catch(e){return {ok:false,message:"We could not connect securely. Please try again."}}}
async function bootstrap(){var r=await api("/api/csrf-bootstrap");if(r.ok)loginCsrf=r.csrf;return r}async function signedIn(){var r=await api("/api/session");if(r.ok){csrf=r.csrf;logout.classList.remove("hide");return r}return null}

/* Task: dependency-free QR version 8-L renderer. It encodes the otpauth URI locally.
   Version 8-L has enough byte capacity for this fixed standard provisioning URI. */
function qr(uri,canvas){
 var n=49, m=Array.from({length:n},function(){return Array(n)}), exp=[],log=[];
 for(var x=0;x<256;x++)exp[x]=0;var v=1;for(var i=0;i<255;i++){exp[i]=v;log[v]=i;v<<=1;if(v&256)v^=285}for(i=255;i<512;i++)exp[i]=exp[i-255];
 function set(r,c,d){if(r>=0&&r<n&&c>=0&&c<n)m[r][c]=d}
 function finder(r,c){for(var y=-1;y<=7;y++)for(var z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))}
 function align(r,c){for(var y=-2;y<=2;y++)for(var z=-2;z<=2;z++)set(r+y,c+z,Math.abs(y)===2||Math.abs(z)===2||(y===0&&z===0))}
 finder(0,0);finder(n-7,0);finder(0,n-7);align(24,42);align(42,24);align(42,42);
 for(i=8;i<n-8;i++){if(m[i][6]===undefined)set(i,6,i%2===0);if(m[6][i]===undefined)set(6,i,i%2===0)}set(41,8,true);
 function bch(d,g){var q=0,t=d;while(t>>1){q++;t>>=1}while(d&&(function(){var a=0,u=d;while(u>>1){a++;u>>=1}return a})()>=q)d^=g<<((function(){var a=0,u=d;while(u>>1){a++;u>>=1}return a})()-q);return d}
 function reserve(mask){var bits=((1<<3)|mask);bits=(bits<<10|bch(bits<<10,0x537))^0x5412;for(var k=0;k<15;k++){var bit=((bits>>k)&1)===1;set(k<6?k:k<8?k+1:n-k-1,8,bit);set(8,k<8?n-k-1:k<9?15-k:14-k,bit)}for(k=0;k<18;k++){bit=((0x85c72>>k)&1)===1;set(Math.floor(k/3),n-11+k%3,bit);set(n-11+k%3,Math.floor(k/3),bit)}}
 function maskf(k,r,c){return [((r+c)%2)===0,(r%2)===0,(c%3)===0,((r+c)%3)===0,((Math.floor(r/2)+Math.floor(c/3))%2)===0,((r*c)%2+(r*c)%3)===0,(((r*c)%2+(r*c)%3)%2)===0,(((r+c)%2+(r*c)%3)%2)===0][k]}
 function rs(block){var gen=[1];for(var a=0;a<24;a++){var next=Array(gen.length+1).fill(0);for(var b=0;b<gen.length;b++){next[b]^=gen[b];next[b+1]^=exp[(log[gen[b]]+a)%255]}gen=next}var out=Array(24).fill(0);block.forEach(function(q){var f=q^out.shift();out.push(0);if(f)for(var j=0;j<24;j++)out[j]^=exp[(log[gen[j+1]]+log[f])%255]});return out}
 var bytes=new TextEncoder().encode(uri);if(bytes.length>192)throw Error("URI too long");var bits=[0,1,0,0];for(i=7;i>=0;i--)bits.push((bytes.length>>i)&1);bytes.forEach(function(q){for(var j=7;j>=0;j--)bits.push((q>>j)&1)});while(bits.length%8)bits.push(0);var data=[];for(i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(i=0;data.length<194;i++)data.push(i%2?0x11:0xec);
 var blocks=[data.slice(0,97),data.slice(97)], ecc=[rs(blocks[0]),rs(blocks[1])], stream=[];for(i=0;i<97;i++){stream.push(blocks[0][i],blocks[1][i])}for(i=0;i<24;i++){stream.push(ecc[0][i],ecc[1][i])}var raw=[];stream.forEach(function(q){for(var j=7;j>=0;j--)raw.push((q>>j)&1)});
 var best=null,bestScore=1e9;
 for(var mk=0;mk<8;mk++){var a=m.map(function(row){return row.slice()});m=a;reserve(mk);var bit=0,up=true;for(var c=n-1;c>0;c-=2){if(c===6)c--;for(var rr=0;rr<n;rr++){var r=up?n-1-rr:rr;for(var cc=0;cc<2;cc++){var col=c-cc;if(m[r][col]===undefined){var d=raw[bit++]===1;if(maskf(mk,r,col))d=!d;m[r][col]=d}}}up=!up}var score=0;for(var r=0;r<n;r++)for(var c=0;c<n;c++){var same=0,d=m[r][c];for(var dy=-1;dy<=1;dy++)for(var dx=-1;dx<=1;dx++)if((dx||dy)&&r+dy>=0&&r+dy<n&&c+dx>=0&&c+dx<n&&m[r+dy][c+dx]===d)same++;if(same>5)score+=same-5}if(score<bestScore){bestScore=score;best=m.map(function(row){return row.slice()})}}
 var scale=6;canvas.width=canvas.height=n*scale;var ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";for(i=0;i<n;i++)for(var j=0;j<n;j++)if(best[i][j])ctx.fillRect(j*scale,i*scale,scale,scale);
}
function signIn(){progress(0);app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="signin-form"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" maxlength="254" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" maxlength="128" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();document.querySelector("#signin-form").onsubmit=async function(e){e.preventDefault();if(!loginCsrf){var b=await bootstrap();if(!b.ok){showError(b.message);return}}var f=new FormData(e.target);try{var r=await fetch("/api/signin",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},body:JSON.stringify({email:f.get("email"),password:f.get("password")})}),d=await r.json();if(!d.ok){showError(d.message);return}activity("Sign-in complete. Secure session created.");notice="Signed in successfully. Next: get your identity code.";go(d.next)}catch(x){showError("We could not connect securely. Please try again.")}};attachHelp()}
function identity(){progress(1);app.innerHTML='<h1>🪪 Check it is you</h1>'+successNotice()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get-code" class="primary">Get identity code</button>'+help();var requestCode=async function(){var r=await api("/api/identity/request","POST",{});if(!r.ok){showError(r.message);return}console.log("Simulated identity code:",r.simulatedCode);entry()};document.querySelector("#get-code").onclick=requestCode;attachHelp();function entry(){app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="identity-form"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();document.querySelector("#identity-form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok){showError(r.message);return}notice="Identity check complete. Next: set up your authenticator.";go(r.next)};document.querySelector("#again").onclick=requestCode;attachHelp()}}
async function createProvision(){var r=await api("/api/authenticator/provision","POST",{});if(!r.ok){showError(r.message);return}provision=r;console.log("Simulated authenticator verification OTP:",r.simulatedOtp);showProvision()}
function setup(){progress(2);app.innerHTML='<h1>📱 Set up your authenticator</h1>'+successNotice()+'<p class="lead">Use a QR code or copy a setup key. You do not need to write anything down.</p><div class="hint">Your authenticator app will give you a six-digit code.</div><div id="form-error" tabindex="-1"></div><button id="show-key" class="primary">Show setup options</button>'+help();document.querySelector("#show-key").onclick=createProvision;attachHelp()}
function showProvision(){progress(2);app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup created. Choose one simple way to add it.</div><p class="lead"><b>Option 1:</b> Scan this QR code with your authenticator app.</p><div class="qr-wrap"><canvas id="qr" aria-label="QR code for Local Bank authenticator setup"></canvas></div><p class="lead"><b>Option 2:</b> Copy the setup key and paste it into your app.</p><div id="private"></div><button id="toggle" class="secondary">Hide setup key</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new-key" class="link">Show a new setup key</button>'+help();qr(provision.provisioningUri,document.querySelector("#qr"));var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<div class="secret code"></div>':'<div class="hint">Setup key is hidden. Select reveal when you are ready.</div>';if(shown)box.firstChild.textContent=provision.secret;document.querySelector("#toggle").textContent=shown?"Hide setup key":"Reveal setup key"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(provision.secret).then(function(){alert("Setup key copied.")}).catch(function(){alert("Select the setup key and copy it.")})};document.querySelector("#next").onclick=function(){go("#confirm")};document.querySelector("#new-key").onclick=createProvision;attachHelp()}
function confirmAuthenticator(){progress(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><div class="hint">Take your time. If needed, show a new setup option and try again.</div><form id="auth-form"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup options again</button>'+help();document.querySelector("#auth-form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok){showError(r.message);return}activity("Authenticator confirmed.");notice="Authenticator confirmed. Next: create your recovery codes.";go(r.next)};document.querySelector("#retry").onclick=function(){provision?showProvision():go("#setup")};attachHelp()}
function recovery(){progress(4);app.innerHTML='<h1>🧾 Save recovery codes</h1>'+successNotice()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create-codes" class="primary">Create recovery codes</button>'+help();document.querySelector("#create-codes").onclick=async function(){var r=await api("/api/recovery/generate","POST",{});if(!r.ok){showError(r.message);return}recoveryCodes=r.codes;console.log("Simulated recovery-code set:",recoveryCodes);showCodes()};attachHelp()}
function showCodes(){app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button>'+help();var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<ul class="codes"></ul>':'<div class="hint">Recovery codes are hidden. Select reveal when you are ready.</div>';if(shown)recoveryCodes.forEach(function(c){var x=document.createElement("li");x.textContent=c;box.firstChild.appendChild(x)});document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(recoveryCodes.join("\\n")).then(function(){alert("Recovery codes copied.")}).catch(function(){alert("Select the codes and copy them.")})};document.querySelector("#done").onclick=function(){go("#saved")};attachHelp()}
async function settings(){progress(4);var r=await api("/api/settings");if(!r.ok){go("#signin");return}app.innerHTML='<h1>⚙️ Security settings</h1><div class="success">MFA is on for <b id="email"></b>.</div><p id="remaining"></p><button id="new-codes" class="primary">Create new recovery codes</button><button id="use-code" class="secondary">Use a recovery code</button>'+help();document.querySelector("#email").textContent=r.email;document.querySelector("#remaining").textContent=r.remaining+" unused code(s) remain.";document.querySelector("#new-codes").onclick=function(){go("#recovery")};document.querySelector("#use-code").onclick=function(){go("#use")};attachHelp()}
function useRecovery(){progress(4);app.innerHTML='<h1>🔑 Use a recovery code</h1><p class="lead">Enter one unused recovery code.</p><form id="use-form"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" placeholder="ABCDE-23456" maxlength="11" pattern="[A-Za-z2-9]{5}-[A-Za-z2-9]{5}" required><button class="primary">Use recovery code</button></form>'+help();document.querySelector("#use-form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/recovery/use","POST",{code:String(new FormData(e.target).get("code")).toUpperCase().trim()});if(!r.ok){showError(r.message);return}app.innerHTML='<h1>✓ Recovery code accepted</h1><div class="success"></div><button id="back" class="primary">Back to settings</button>'+help();document.querySelector(".success").textContent=r.message;document.querySelector("#back").onclick=function(){go("#settings")};attachHelp()};attachHelp()}
function saved(){progress(4);app.innerHTML='<h1>🎉 Security setup complete</h1><div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="view-settings" class="primary">View security settings</button>'+help();document.querySelector("#view-settings").onclick=function(){go("#settings")};attachHelp()}
async function render(){var route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin"){await bootstrap();signIn();return}var state=await signedIn();if(!state){go("#signin");return}if(!state.identityVerified&&route!=="#identity"){go("#identity");return}if(!state.mfaEnabled&&["#recovery","#saved","#settings","#use"].includes(route)){go(state.provisioned?"#confirm":"#setup");return}if(state.mfaEnabled&&state.recoveryCount===0&&["#saved","#settings","#use"].includes(route)){go("#recovery");return}({"#identity":identity,"#setup":setup,"#confirm":confirmAuthenticator,"#recovery":recovery,"#saved":saved,"#settings":settings,"#use":useRecovery})[route]()}
logout.onclick=async function(){var r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;recoveryCodes=[];activity("Secure session ended.");go("#signin")}};addEventListener("hashchange",render);render();
})();</script></body></html>`;}

const certificate=readFileSync("certs/cert.pem"), privateKey=readFileSync("certs/key.pem");
/* Requirement 3: Bun TLS server using supplied localhost mkcert files. */
Bun.serve({
  port:3000, tls:{cert:certificate,key:privateKey},
  fetch:async request=>{
    const nonce=random(18);
    try {
      const url=new URL(request.url), origin=request.headers.get("origin");
      if(request.headers.get("x-forwarded-proto")==="http")return new Response("Secure connection required.",{status:426,headers:securityHeaders(nonce)});
      if(origin&&!trustedOrigins.has(origin))return new Response("Not allowed.",{status:403,headers:securityHeaders(nonce)});
      const cors=origin?{"Access-Control-Allow-Origin":origin}:{};
      if(request.method==="OPTIONS")return new Response(null,{status:204,headers:{...securityHeaders(nonce),...cors,"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, X-CSRF-Token, X-Login-CSRF"}});
      if(url.pathname.startsWith("/api/")){const r=await api(request,url.pathname,nonce);for(const [k,v] of Object.entries(cors))r.headers.set(k,v);return r;}
      if(request.method==="GET"&&(url.pathname==="/"||url.pathname==="/index.html"))return new Response(page(nonce),{headers:{...securityHeaders(nonce),...cors,"Content-Type":"text/html; charset=utf-8"}});
      return new Response("Page not found.",{status:404,headers:securityHeaders(nonce)});
    } catch {
      return new Response("We could not complete that request. Please try again.",{status:500,headers:securityHeaders(nonce)});
    }
  }
});
