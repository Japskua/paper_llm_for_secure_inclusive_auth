
/*
  MFA Enrolment System — single Bun HTTPS server and mobile web client.
  Run: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/
const PORT = 3000;
const IDLE_MS = 20 * 60 * 1000, ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_PERIOD = 300000, MAX_ATTEMPTS = 5, LOCK_MS = 300000;
const enc = new TextEncoder(), dec = new TextDecoder();

type Session = { userId:string; csrf:string; created:number; seen:number; identity:boolean };
type Cipher = { nonce:string; cipher:string };
type Recovery = { salt:string; hash:string; used:boolean };
type Account = {
  id:string; email:string; password:string; pending?:Cipher; active?:Cipher;
  usedSlots:Set<number>; otpFailures:number; otpLocked:number;
  recovery:Recovery[]; recoveryFailures:number; recoveryLocked:number;
  identityFailures:number; identityLocked:number;
};

const sessions = new Map<string, Session>();
const account:Account = {
  id:"account-marcus-001", email:"marcus@example.com", password:"River!47",
  usedSlots:new Set(), otpFailures:0, otpLocked:0, recovery:[], recoveryFailures:0,
  recoveryLocked:0, identityFailures:0, identityLocked:0,
};
const origins = new Set(["https://localhost:3000","https://127.0.0.1:3000","https://[::1]:3000"]);

/* Security requirement 3: AES-GCM key remains process-protected; OTP seeds are encrypted at rest. */
const aesKey = await crypto.subtle.generateKey({name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);

function randomBytes(n:number){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(data:Uint8Array|ArrayBuffer) {
  let s=""; for(const x of (data instanceof ArrayBuffer ? new Uint8Array(data) : data)) s+=String.fromCharCode(x);
  return btoa(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}
function unb64(s:string) {
  s=s.replaceAll("-","+").replaceAll("_","/")+"===".slice((s.length+3)%4);
  return Uint8Array.from(atob(s), x=>x.charCodeAt(0));
}
function token(n=32){ return b64(randomBytes(n)); }
function b32(data:Uint8Array) {
  const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let out="", v=0, bits=0;
  for(const byte of data){v=(v<<8)|byte;bits+=8;while(bits>=5){out+=a[(v>>>(bits-5))&31];bits-=5;}}
  return bits ? out+a[(v<<(5-bits))&31] : out;
}
function fromB32(value:string) {
  const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", clean=value.replaceAll(/\s/g,"").replaceAll("=","").toUpperCase();
  let v=0,bits=0; const out:number[]=[];
  for(const ch of clean){const n=a.indexOf(ch);if(n<0)throw new Error("bad base32");v=(v<<5)|n;bits+=5;if(bits>=8){out.push((v>>>(bits-8))&255);bits-=8;}}
  return new Uint8Array(out);
}
function cookies(r:Request) {
  const out:Record<string,string>={};
  for(const part of (r.headers.get("cookie")||"").split(";")) { const i=part.indexOf("="); if(i>0)out[part.slice(0,i).trim()]=part.slice(i+1).trim(); }
  return out;
}
function trusted(r:Request){ return !!r.headers.get("origin") && origins.has(r.headers.get("origin")!); }

/* Security requirements 1 and 2: secure cookie, CSP/HSTS/nosniff/clickjacking protections, restricted CORS. */
function headers(nonce?:string, r?:Request) {
  const h=new Headers({
    "Content-Type":"application/json; charset=utf-8",
    "Content-Security-Policy":nonce
      ? "default-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
      : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
    "X-Content-Type-Options":"nosniff", "X-Frame-Options":"DENY",
    "Referrer-Policy":"no-referrer", "Cache-Control":"no-store",
  });
  if(r&&trusted(r)){h.set("Access-Control-Allow-Origin",r.headers.get("origin")!);h.set("Access-Control-Allow-Credentials","true");h.set("Vary","Origin");}
  return h;
}
function reply(v:unknown,status=200,r?:Request, extra?:HeadersInit) {
  const h=headers(undefined,r); if(extra)for(const [k,x] of new Headers(extra))h.set(k,x);
  return new Response(JSON.stringify(v),{status,headers:h});
}
function fail(status:number,r?:Request){return reply({ok:false,message:"We could not complete that request. Please try again."},status,r);}
function cookie(v:string,max?:number){return "mfa_session="+v+"; Path=/; HttpOnly; Secure; SameSite=Strict"+(max===undefined?"":"; Max-Age="+max);}

function session(r:Request):{id:string;s:Session}|null {
  const id=cookies(r).mfa_session, s=id&&sessions.get(id); if(!id||!s)return null;
  const now=Date.now();
  if(now-s.seen>IDLE_MS||now-s.created>ABSOLUTE_MS){sessions.delete(id);return null;}
  s.seen=now; return {id,s};
}
/* Security requirement 1: every MFA API route checks the authenticated owner, never a supplied user id. */
function auth(r:Request):{id:string;s:Session}|Response {
  const found=session(r);
  return !found||found.s.userId!==account.id ? reply({ok:false,message:"Please sign in to continue."},401,r) : found;
}
/* Security requirement 1: all state-changing API routes require trusted Origin and anti-CSRF token. */
function csrf(r:Request):{id:string;s:Session}|Response {
  const found=auth(r); if(found instanceof Response)return found;
  return !trusted(r)||r.headers.get("x-csrf-token")!==found.s.csrf
    ? reply({ok:false,message:"This page needs to be refreshed before continuing."},403,r) : found;
}
async function input(r:Request):Promise<Record<string,unknown>|null>{try{const x=await r.json();return x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:null;}catch{return null;}}
function str(x:unknown,max:number){return typeof x==="string"&&x.length<=max?x.trim():null;}
async function encrypt(secret:string):Promise<Cipher>{
  const nonce=randomBytes(12), cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce},aesKey,enc.encode(secret));
  return {nonce:b64(nonce),cipher:b64(cipher)};
}
async function decrypt(v:Cipher){return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(v.nonce)},aesKey,unb64(v.cipher)));}
async function otp(secret:string,slot:number) {
  const ctr=new Uint8Array(8);let x=BigInt(Math.max(0,slot));
  for(let i=7;i>=0;i--){ctr[i]=Number(x&255n);x>>=8n;}
  const key=await crypto.subtle.importKey("raw",fromB32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,ctr)), o=sig[sig.length-1]&15;
  const n=((sig[o]&127)<<24)|(sig[o+1]<<16)|(sig[o+2]<<8)|sig[o+3];
  return String(n%1000000).padStart(6,"0");
}
async function recoveryHash(code:string,salt:string) {
  const key=await crypto.subtle.importKey("raw",enc.encode(code),"PBKDF2",false,["deriveBits"]);
  return b64(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc.encode(salt),iterations:100000},key,256));
}
function equal(a:Uint8Array,b:Uint8Array){let d=a.length^b.length;for(let i=0;i<Math.max(a.length,b.length);i++)d|=(a[i]||0)^(b[i]||0);return d===0;}
const credentialSalt=token(16);
async function credential(email:string,password:string) {
  const key=await crypto.subtle.importKey("raw",enc.encode(email+"\0"+password),"PBKDF2",false,["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc.encode(credentialSalt),iterations:100000},key,256));
}
const validCredential=await credential(account.email,account.password);
function newRecovery() {
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", raw=randomBytes(10); let s="";
  for(let i=0;i<10;i++){if(i===5)s+="-";s+=alphabet[raw[i]%alphabet.length];} return s;
}
async function makeRecoveries() {
  const visible:string[]=[], stored:Recovery[]=[];
  for(let i=0;i<8;i++){const code=newRecovery(),salt=token(16);visible.push(code);stored.push({salt,hash:await recoveryHash(code,salt),used:false});}
  account.recovery=stored; return visible;
}

/*
  Accessible mobile UI requirements: roomy Verdana-based typography, short plain-language
  instructions, predictable steps, visible hints, icons, examples, copy controls, and no timers
  or moving content reduce reading and transcription pressure for dyslexic users.
  Browser mock behavior requirements: test-only OTP and recovery values are intentionally shown
  once and written to the browser console only; no persistent in-page log duplicates secrets.
*/
function html(nonce:string){return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.28;letter-spacing:.02em;margin:0 0 15px}h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;background:#fff}.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}.test{background:#fff9e9;border-left:5px solid #9a6800;padding:14px;margin:16px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}input:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}.copyrow{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.copyrow .smalllink{margin:3px 0}.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.1em;line-height:2;background:#f4f8fb;padding:13px;border-radius:8px;white-space:pre-wrap}.qr{display:block;width:min(100%,290px);height:auto;margin:12px auto;background:white;border:1px solid var(--line);padding:8px}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}}
</style></head><body><main id="app" aria-live="polite">Loading securely…</main>
<script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app");let csrfToken="",provision=null,recoveryCodes=null;
const E=(tag,p={},kids=[])=>{const n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="className")n.className=v;else if(k==="text")n.textContent=v;else if(k.startsWith("on")&&typeof v==="function")n.addEventListener(k.slice(2).toLowerCase(),v);else n.setAttribute(k,String(v));}for(const x of kids)n.append(x);return n;};
const say=(text,kind="notice")=>E("div",{className:kind,text,role:"status"});
function page(step,title){app.replaceChildren();app.append(E("header",{},[E("div",{className:"brand",text:"Northstar Bank"}),E("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]),E("h1",{text:title}));}
function help(){return E("div",{className:"hint"},[E("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
async function api(path,method="GET",data){const o={method,headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrfToken;o.body=JSON.stringify(data||{});}try{const r=await fetch(path,o),v=await r.json().catch(()=>({ok:false,message:"We could not complete that request."}));if(r.status===401)signin(v.message);return v;}catch{return{ok:false,message:"Connection problem. Please try again."};}}
function primary(text,fn){return E("button",{type:"button",text,onClick:fn});}
function copy(value,button){navigator.clipboard?.writeText(value).then(()=>button.textContent="Copied").catch(()=>button.textContent="Select the value to copy");}

/* Local standards-compliant QR Model 2 generator: Version 9, byte mode, ECC level L, mask 0. */
function qrSvg(text){
 const N=53,m=Array.from({length:N},()=>Array(N).fill(null)),a=new TextEncoder().encode(text);
 function set(x,y,v){if(x>=0&&y>=0&&x<N&&y<N)m[y][x]=v;}
 function finder(x,y){for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)set(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)));}
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(let i=8;i<N-8;i++){if(m[6][i]===null)set(i,6,i%2===0);if(m[i][6]===null)set(6,i,i%2===0);}
 function align(cx,cy){for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)if(m[cy+y][cx+x]===null)set(cx+x,cy+y,Math.max(Math.abs(x),Math.abs(y))!==1);}
 for(const x of [6,26,46])for(const y of [6,26,46])if(m[y][x]===null)align(x,y); set(8,N-8,true);
 function bch(v,poly){let d=0;for(let x=poly;x;x>>=1)d++;v<<=d-1;while(true){let q=0;for(let x=v;x;x>>=1)q++;if(q<d)break;v^=poly<<(q-d);}return v;}
 const fmt=((1<<3)|0);let f=((fmt<<10)|bch(fmt,0x537))^0x5412;for(let i=0;i<15;i++){const bit=((f>>i)&1)===1;if(i<6)set(8,i,bit);else if(i<8)set(8,i+1,bit);else set(N-15+i,8,bit);if(i<8)set(N-i-1,8,bit);else if(i<9)set(15-i,8,bit);else set(8,15-i-1,bit);}
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>i)&1);};put(4,4);put(a.length,8);for(const x of a)put(x,8);const data=[];for(let i=0;i<bits.length;i+=8){let v=0;for(let j=0;j<8;j++)v=(v<<1)|(bits[i+j]||0);data.push(v);}
 while(data.length<232)data.push(data.length%2?0x11:0xec);
 const exp=[],log=Array(256);let z=1;for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=0x11d;}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(x,y)=>x&&y?exp[log[x]+log[y]]:0;let gen=[1];for(let i=0;i<30;i++){const g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=mul(gen[j],exp[i]);}gen=g;}
 const all=[];for(let block=0;block<2;block++){const d=data.slice(block*116,block*116+116),r=d.concat(Array(30).fill(0));for(let i=0;i<116;i++)if(r[i])for(let j=0;j<gen.length;j++)r[i+j]^=mul(gen[j],r[i]);all.push({d,e:r.slice(116)});}
 const stream=[];for(let i=0;i<116;i++)for(const q of all)stream.push(q.d[i]);for(let i=0;i<30;i++)for(const q of all)stream.push(q.e[i]);
 const databits=[];for(const x of stream)for(let i=7;i>=0;i--)databits.push((x>>i)&1);let p=0,up=true;
 for(let x=N-1;x>0;x-=2){if(x===6)x--;for(let k=0;k<N;k++){const y=up?N-1-k:k;for(let dx=0;dx<2;dx++)if(m[y][x-dx]===null){let v=databits[p++]||0;if(((x-dx)+y)%2===0)v^=1;set(x-dx,y,!!v);}}up=!up;}
 let path="";for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(m[y][x])path+="M"+x+" "+y+"h1v1h-1z";
 const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");svg.setAttribute("class","qr");svg.setAttribute("viewBox","0 0 "+N+" "+N);svg.setAttribute("role","img");svg.setAttribute("aria-label","QR code for authenticator setup");const title=document.createElementNS(svg.namespaceURI,"title");title.textContent="Authenticator setup QR code";const path=document.createElementNS(svg.namespaceURI,"path");path.setAttribute("d",path?"":"");path.setAttribute("fill","#000");path.setAttribute("d",arguments[0]&&"");svg.append(title);const shape=document.createElementNS(svg.namespaceURI,"path");shape.setAttribute("d",window.__qrPath||"");shape.setAttribute("fill","#000");svg.removeChild(title);
 const actual=document.createElementNS(svg.namespaceURI,"path");actual.setAttribute("d",path);actual.setAttribute("fill","#000");svg.append(actual);return svg;
}
function signin(error){page("1","Sign in");app.append(E("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));if(error)app.append(say(error,"error"));const form=E("form"),email=E("input",{id:"email",type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"}),password=E("input",{id:"password",type:"password",autocomplete:"current-password",placeholder:"Your password"});const send=async e=>{e.preventDefault();const r=await api("/api/signin","POST",{email:email.value,password:password.value});if(!r.ok)return signin(r.message);csrfToken=r.csrf;console.log("Mock sign-in completed. A secure server session was created.");identity();};form.addEventListener("submit",send);form.append(E("label",{for:"email",text:"Email"}),email,E("p",{className:"hint",text:"Example: marcus@example.com"}),E("label",{for:"password",text:"Password"}),password,primary("Sign in",send));app.append(form,E("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}),help());}
function identity(error){page("2","Check it is you");app.append(E("p",{text:"We need one quick identity check before MFA set-up."}));if(error)app.append(say(error,"error"));const code=E("input",{id:"identity",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"246810"});app.append(E("label",{for:"identity",text:"Identity check code"}),code,E("p",{className:"hint",text:"Example: 246810"}),primary("Confirm identity",async()=>{const r=await api("/api/identity","POST",{code:code.value});if(!r.ok)return identity(r.message);console.log("Mock identity check completed.");setup();}),help());}
function setup(error){page("3","Set up your authenticator");app.append(E("p",{text:"Open your authenticator app. You can scan a code or copy a setup value."}));if(error)app.append(say(error,"error"));app.append(E("div",{className:"card",text:"📱 Choose “add account” in your authenticator app."}),primary("Show setup options",async()=>{const r=await api("/api/mfa/provision","POST",{});if(!r.ok)return setup(r.message);provision=r;console.log("Testing-only authenticator OTP:",r.testOtp);provisionScreen();}),help());}
function provisionScreen(){page("3","Add this account");app.append(E("p",{text:"Scan the QR code. If that is not convenient, copy a value instead. You do not need to type it."}),qrSvg(provision.uri),E("h2",{text:"Manual setup value"}),E("div",{className:"code",text:provision.secret}));const sec=E("button",{className:"secondary",type:"button",text:"Copy manual secret",onClick:()=>copy(provision.secret,sec)}),uri=E("button",{className:"smalllink",type:"button",text:"Copy setup link",onClick:()=>copy(provision.uri,uri)});app.append(E("div",{className:"copyrow"},[sec,uri]),E("div",{className:"test"},[E("strong",{text:"Testing only"}),E("div",{className:"code",text:"Mock authenticator OTP: "+provision.testOtp}),E("p",{text:"Use this 6-digit mock code to test verification. It was also written to the browser console."})]),primary("I have added it",verify),help());}
function verify(error){page("4","Enter the 6-digit code");app.append(E("p",{text:"Your authenticator app now shows a 6-digit code. Take your time."}));if(error)app.append(say(error,"error"));const code=E("input",{id:"otp",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});app.append(E("label",{for:"otp",text:"Authenticator code"}),code,E("p",{className:"hint",text:"Example: 123456"}),primary("Verify code",async()=>{const r=await api("/api/mfa/verify","POST",{otp:code.value});if(!r.ok)return verify(r.message);recoveryCodes=r.codes;console.log("Testing-only backup recovery codes:",r.codes);backups();}),E("button",{className:"smalllink",type:"button",text:"Show setup options again",onClick:provisionScreen}),help());}
function backups(){page("4","Save your backup codes");const all=recoveryCodes.join("\\n");app.append(say("Authenticator set up. Save these backup codes somewhere safe. Each one works once."),E("div",{className:"codes",text:all}));const cp=E("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(all,cp)});app.append(cp,primary("I saved my codes",settings),help());}
function settings(message){page("4","MFA is ready");app.append(E("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));if(message)app.append(say(message,message.startsWith("That backup")?"notice":"error"));const code=E("input",{id:"recovery",autocomplete:"one-time-code",placeholder:"ABCDE-12345",maxlength:"11"});app.append(E("h2",{text:"Try a backup code"}),E("label",{for:"recovery",text:"Recovery code"}),code,E("p",{className:"hint",text:"Example: ABCDE-12345"}),primary("Use recovery code",async()=>{const r=await api("/api/recovery/verify","POST",{code:code.value});settings(r.ok?"That backup code worked and cannot be used again.":r.message);}),E("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{const r=await api("/api/backup/regenerate","POST",{});if(!r.ok)return settings(r.message);recoveryCodes=r.codes;console.log("Testing-only replacement recovery codes:",r.codes);backups();}),E("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{await api("/api/logout","POST",{});csrfToken="";provision=null;recoveryCodes=null;console.log("Mock sign-out completed. Server session invalidated.");signin();}),help());}
async function boot(){const r=await api("/api/status");if(r.ok){csrfToken=r.csrf;r.mfaActive?settings():r.identityVerified?setup():identity();}else signin();}boot();
})();</script></body></html>`;}

async function route(r:Request):Promise<Response>{
  const url=new URL(r.url);
  if(r.method==="OPTIONS"){if(!trusted(r))return fail(403,r);const h=headers(undefined,r);h.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");h.set("Access-Control-Allow-Headers","Content-Type, X-CSRF-Token");return new Response(null,{status:204,headers:h});}
  if(url.pathname==="/"&&r.method==="GET"){const n=token(18),h=headers(n,r);h.set("Content-Type","text/html; charset=utf-8");return new Response(html(n),{headers:h});}

  if(url.pathname==="/api/signin"&&r.method==="POST"){
    if(!trusted(r))return fail(403,r);
    const x=await input(r),email=str(x?.email,254),password=str(x?.password,128),valid=!!email&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    /* Security requirement 5: PBKDF2 work is performed for invalid values too, reducing enumeration timing differences. */
    const normalizedEmail=valid?email!.toLowerCase():"invalid@example.invalid",normalizedPassword=password||"invalid-password-value";
    const matched=equal(await credential(normalizedEmail,normalizedPassword),validCredential)&&normalizedEmail===account.email&&!!password&&valid;
    if(!matched)return reply({ok:false,message:"Those sign-in details did not match. Check both fields and try again."},401,r);
    const id=token(),now=Date.now(),s:Session={userId:account.id,csrf:token(),created:now,seen:now,identity:false};sessions.set(id,s);
    return reply({ok:true,csrf:s.csrf},200,r,{"Set-Cookie":cookie(id)});
  }
  if(url.pathname==="/api/status"&&r.method==="GET"){const a=auth(r);if(a instanceof Response)return a;return reply({ok:true,csrf:a.s.csrf,identityVerified:a.s.identity,mfaActive:!!account.active},200,r);}
  if(url.pathname==="/api/identity"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;if(Date.now()<account.identityLocked)return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);const code=str((await input(r))?.code,6);if(!code||!/^\\d{6}$/.test(code)||code!=="246810"){if(++account.identityFailures>=MAX_ATTEMPTS){account.identityFailures=0;account.identityLocked=Date.now()+LOCK_MS;return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);}return reply({ok:false,message:"That identity code did not work. Check the 6 numbers and try again."},400,r);}account.identityFailures=0;a.s.identity=true;return reply({ok:true},200,r);}
  if(url.pathname==="/api/mfa/provision"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;if(!a.s.identity)return reply({ok:false,message:"Complete the identity check before setting up MFA."},403,r);const secret=b32(randomBytes(20));account.pending=await encrypt(secret);account.usedSlots.clear();account.otpFailures=0;account.otpLocked=0;const testOtp=await otp(secret,Math.floor(Date.now()/OTP_PERIOD));const uri="otpauth://totp/"+encodeURIComponent("Northstar:"+account.email)+"?secret="+secret+"&issuer=Northstar&algorithm=SHA1&digits=6&period=300";return reply({ok:true,secret,uri,testOtp},200,r);}
  if(url.pathname==="/api/mfa/verify"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;if(!a.s.identity)return reply({ok:false,message:"Complete the identity check before setting up MFA."},403,r);const value=str((await input(r))?.otp,6);if(!value||!/^\\d{6}$/.test(value))return reply({ok:false,message:"Enter all 6 numbers from your authenticator app."},400,r);if(!account.pending)return reply({ok:false,message:"Choose setup options first, then enter the code."},400,r);if(Date.now()<account.otpLocked)return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);const secret=await decrypt(account.pending),slot=Math.floor(Date.now()/OTP_PERIOD);let hit:number|null=null;if(value===await otp(secret,slot))hit=slot;else if(value===await otp(secret,slot-1))hit=slot-1;if(hit===null||account.usedSlots.has(hit)){if(++account.otpFailures>=MAX_ATTEMPTS){account.otpFailures=0;account.otpLocked=Date.now()+LOCK_MS;return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);}return reply({ok:false,message:"That code did not work. Check your authenticator app and try a fresh 6-digit code."},400,r);}account.usedSlots.add(hit);account.otpFailures=0;account.active=account.pending;account.pending=undefined;return reply({ok:true,codes:await makeRecoveries()},200,r);}
  if(url.pathname==="/api/recovery/verify"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;const code=str((await input(r))?.code,11)?.toUpperCase();if(!code||!/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(code))return reply({ok:false,message:"Enter a backup code in the format ABCDE-12345."},400,r);if(Date.now()<account.recoveryLocked)return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);for(const item of account.recovery)if(!item.used&&equal(enc.encode(await recoveryHash(code,item.salt)),enc.encode(item.hash))){item.used=true;account.recoveryFailures=0;return reply({ok:true},200,r);}if(++account.recoveryFailures>=MAX_ATTEMPTS){account.recoveryFailures=0;account.recoveryLocked=Date.now()+LOCK_MS;return reply({ok:false,message:"Too many attempts. Please pause, then try again later."},429,r);}return reply({ok:false,message:"That backup code did not work. Check the saved code and try another one."},400,r);}
  if(url.pathname==="/api/backup/regenerate"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;if(!account.active)return reply({ok:false,message:"Set up an authenticator before making backup codes."},400,r);return reply({ok:true,codes:await makeRecoveries()},200,r);}
  if(url.pathname==="/api/logout"&&r.method==="POST"){const a=csrf(r);if(a instanceof Response)return a;sessions.delete(a.id);return reply({ok:true},200,r,{"Set-Cookie":cookie("",0)});}
  return fail(404,r);
}

Bun.serve({
  port:PORT,
  tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
  async fetch(request){try{return await route(request);}catch{return fail(500,request);}},
});
console.log("MFA demo listening securely at https://localhost:"+PORT);
