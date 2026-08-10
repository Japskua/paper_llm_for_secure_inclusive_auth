
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
/* Requirement 4: malformed JSON and non-object payloads are rejected. */
async function payload(r:Request){try{const x=await r.json();return x&&typeof x==="object"&&!Array.isArray(x)?x:null;}catch{return null;}}
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
:root{--ink:#172331;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--bad:#8b2424;--good:#125b35}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:16px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 28px}header{display:flex;gap:10px;align-items:center}.mark{background:var(--blue);color:#fff;border-radius:12px;padding:8px 14px;font-size:22px}h1{font-size:1.35rem;margin:0}h2{line-height:1.3;margin-top:0}.hint{color:#526273;font-size:.88rem}.steps{display:flex;gap:4px;margin:18px 0}.steps span{flex:1;border-bottom:4px solid var(--line);font-size:.72rem;text-align:center;padding-bottom:4px}.steps .on{border-color:var(--blue);color:#073c83;font-weight:bold}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:20px}.notice{padding:11px;border-radius:9px;background:var(--soft);margin:12px 0}.bad{background:#fff0f0;color:var(--bad)}.success{background:#effaf2;color:var(--good)}label{display:block;font-weight:bold;margin:15px 0 5px}input,button{width:100%;min-height:52px;border-radius:10px;font:inherit}input{border:2px solid #9eafc0;padding:10px;letter-spacing:.05em}button{border:0;padding:10px;margin-top:12px;font-weight:bold;cursor:pointer}.primary{background:var(--blue);color:#fff}.secondary{background:#fff;color:#073c83;border:2px solid var(--blue)}button:focus,input:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}.secret,.code,#logs-output{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px}.row button{flex:1}.qr{width:250px;height:250px;display:block;margin:15px auto;border:8px solid white;image-rendering:pixelated}.logs{margin-top:16px;padding:14px}.logs h2{font-size:1rem;margin-bottom:8px}#logs-output{white-space:pre-wrap;min-height:42px;font-size:.78rem;line-height:1.45}@media(max-width:390px){.codes{grid-template-columns:1fr}.row{flex-direction:column}}
</style></head><body><main><header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><div class="hint">Security setup</div></div></header><nav class="steps" aria-label="Setup steps"><span data-s="1">1. Confirm</span><span data-s="2">2. App</span><span data-s="3">3. Check</span><span data-s="4">4. Save</span></nav><section id="app" class="card" aria-live="polite"></section><p class="hint">Take your time. There is no reading timer.</p><aside class="logs" aria-label="Logs"><h2>Logs</h2><div id="logs-output">Ready.</div></aside></main>
<script nonce="${nonce}">
"use strict";
const app=document.querySelector("#app");
const logs=document.querySelector("#logs-output");
const TEST=${TEST_MOCK_LOGGING?"true":"false"};
let csrf="",s="",uri="",backup=[];

function esc(v){const x=document.createElement("span");x.textContent=String(v);return x.innerHTML}
function log(a,v){console.log(a,v===undefined?"":v);logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+a+(v===undefined?"":" "+(Array.isArray(v)?v.join(", "):v))}
function step(n){document.querySelectorAll("[data-s]").forEach(function(x){x.classList.toggle("on",+x.dataset.s===n)})}
function note(t,k=""){return '<div class="notice '+k+'">'+esc(t)+"</div>"}
function help(){return "<details><summary>Help with this step</summary><p>Pause or retry at any time. There is no reading timer.</p></details>"}
function message(text){const target=document.querySelector("#msg");if(target)target.textContent=text}
async function api(path,data={}){
  const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});
  const d=await r.json().catch(function(){return {message:"Please try again."}});
  if(r.status===401)signin("Your session ended. Please sign in again.");
  return {r:r,d:d};
}
async function copyText(value,name){
  try{await navigator.clipboard.writeText(value);message(name+" copied. You can paste it somewhere safe.")}
  catch{message("Copy did not work here. You can select the text and copy it instead.")}
}

/* A self-contained QR encoder: version 8-L byte-mode QR, sufficient for this otpauth URI. */
function qrMatrix(text){
  const size=49, dataCapacity=192, ecLength=24, blocks=2;
  const matrix=Array.from({length:size},function(){return Array(size).fill(false)});
  const fixed=Array.from({length:size},function(){return Array(size).fill(false)});
  function put(x,y,v){if(x>=0&&y>=0&&x<size&&y<size){matrix[y][x]=v;fixed[y][x]=true}}
  function finder(x,y){
    for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++)put(x+dx,y+dy,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)));
  }
  function align(cx,cy){
    for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)put(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1);
  }
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(const p of [[24,24],[42,24],[24,42],[42,42]])align(p[0],p[1]);
  for(let i=8;i<size-8;i++){put(i,6,i%2===0);put(6,i,i%2===0)}
  put(8,size-8,true);
  function bch(v,poly){let x=v;while((x.toString(2).length)>=(poly.toString(2).length)){x^=poly<<(x.toString(2).length-poly.toString(2).length)}return x}
  const versionBits=(8<<12)|bch(8<<12,0x1f25);
  for(let i=0;i<18;i++){const bit=((versionBits>>>i)&1)===1;put(size-11+i%3,Math.floor(i/3),bit);put(Math.floor(i/3),size-11+i%3,bit)}
  const bytes=Array.from(new TextEncoder().encode(text));
  if(bytes.length>dataCapacity-2)throw new Error("Setup link is too long.");
  const bits=[0,1,0,0];
  for(let i=7;i>=0;i--)bits.push((bytes.length>>>i)&1);
  bytes.forEach(function(b){for(let i=7;i>=0;i--)bits.push((b>>>i)&1)});
  while(bits.length%8)bits.push(0);
  const raw=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];raw.push(b)}
  for(let pad=0;raw.length<dataCapacity;pad++)raw.push(pad%2?0x11:0xec);
  const exp=[],logTable=Array(256).fill(0);let q=1;
  for(let i=0;i<255;i++){exp[i]=q;logTable[q]=i;q<<=1;if(q&256)q^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
  function mul(a,b){return !a||!b?0:exp[logTable[a]+logTable[b]]}
  const gen=[1];for(let i=0;i<ecLength;i++){gen.push(0);for(let j=gen.length-1;j>0;j--)gen[j]=gen[j-1]^mul(gen[j],exp[i]);gen[0]=mul(gen[0],exp[i])}
  function ecc(part){const rem=Array(ecLength).fill(0);part.forEach(function(v){const f=v^rem.shift();rem.push(0);for(let j=0;j<ecLength;j++)rem[j]^=mul(gen[j+1],f)});return rem}
  const chunks=[raw.slice(0,96),raw.slice(96,192)], parity=chunks.map(ecc), stream=[];
  for(let i=0;i<96;i++)for(let b=0;b<blocks;b++)stream.push(chunks[b][i]);
  for(let i=0;i<ecLength;i++)for(let b=0;b<blocks;b++)stream.push(parity[b][i]);
  let bitIndex=0,up=true;
  for(let right=size-1;right>0;right-=2){
    if(right===6)right--;
    for(let z=0;z<size;z++){
      const y=up?size-1-z:z;
      for(let dx=0;dx<2;dx++){const x=right-dx;if(!fixed[y][x]){const bit=bitIndex<stream.length*8?((stream[Math.floor(bitIndex/8)]>>>(7-bitIndex%8))&1):0;matrix[y][x]=!!bit;bitIndex++}}
    }
    up=!up;
  }
  function format(mask){
    const value=((1<<3)|mask)<<10;
    const bits=(value|bch(value,0x537))^0x5412;
    for(let i=0;i<=5;i++)matrix[i][8]=((bits>>>i)&1)===1;
    matrix[7][8]=((bits>>>6)&1)===1;matrix[8][8]=((bits>>>7)&1)===1;matrix[8][7]=((bits>>>8)&1)===1;
    for(let i=9;i<15;i++)matrix[8][14-i]=((bits>>>i)&1)===1;
    for(let i=0;i<8;i++)matrix[8][size-1-i]=((bits>>>i)&1)===1;
    for(let i=8;i<15;i++)matrix[size-15+i][8]=((bits>>>i)&1)===1;
  }
  function masked(mask){
    const out=matrix.map(function(row){return row.slice()});
    for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(!fixed[y][x]){
      const m=[(x+y)%2===0,y%2===0,x%3===0,(x+y)%3===0,(Math.floor(y/2)+Math.floor(x/3))%2===0,(x*y)%2+(x*y)%3===0,((x*y)%2+(x*y)%3)%2===0,((x+y)%2+(x*y)%3)%2===0][mask];
      if(m)out[y][x]=!out[y][x];
    }
    return out;
  }
  function penalty(m){
    let p=0;
    for(let y=0;y<size;y++)for(let x=0;x<size;x++){
      let run=1;while(x+run<size&&m[y][x+run]===m[y][x])run++;if(run>=5)p+=3+run-5;
      run=1;while(y+run<size&&m[y+run][x]===m[y][x])run++;if(run>=5)p+=3+run-5;
      if(x<size-1&&y<size-1&&m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x]&&m[y][x]===m[y+1][x+1])p+=3;
    }
    for(let y=0;y<size;y++)for(let x=0;x<size-6;x++){const a=m[y].slice(x,x+7).map(Number).join("");if(a==="1011101")p+=40}
    for(let x=0;x<size;x++)for(let y=0;y<size-6;y++){let a="";for(let i=0;i<7;i++)a+=m[y+i][x]?1:0;if(a==="1011101")p+=40}
    let dark=0;m.forEach(function(row){row.forEach(function(v){if(v)dark++})});p+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;
    return p;
  }
  let best=null,bestScore=Infinity;
  for(let mask=0;mask<8;mask++){const candidate=masked(mask);const saved=matrix.map(function(row){return row.slice()});for(let y=0;y<size;y++)matrix[y]=candidate[y];format(mask);const score=penalty(matrix);if(score<bestScore){bestScore=score;best=matrix.map(function(row){return row.slice()})}for(let y=0;y<size;y++)matrix[y]=saved[y]}
  return best;
}
function renderQR(canvas,text){
  const matrix=qrMatrix(text), modules=matrix.length, quiet=4, scale=5;
  canvas.width=canvas.height=(modules+quiet*2)*scale;
  const c=canvas.getContext("2d");c.fillStyle="#fff";c.fillRect(0,0,canvas.width,canvas.height);c.fillStyle="#000";
  for(let y=0;y<modules;y++)for(let x=0;x<modules;x++)if(matrix[y][x])c.fillRect((x+quiet)*scale,(y+quiet)*scale,scale,scale);
}

function signin(msg=""){
  step(1);
  app.innerHTML="<h2>Confirm your account</h2><p>Use your bank email and password.</p>"+(TEST?note("Test mode is on. Mock values are shown in Logs.","success"):"")+(msg?note(msg):"")+'<label for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"><button class="primary" id="go">Continue</button>'+help();
  const go=app.querySelector("#go"),email=app.querySelector("#email"),password=app.querySelector("#password");
  go.onclick=async function(){
    const r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email.value,password:password.value})}),d=await r.json();
    if(!r.ok){app.insertAdjacentHTML("afterbegin",note(d.message,"bad"));return}
    csrf=d.csrf;log("Sign-in simulation completed.");d.mfaEnabled?account("Your authenticator is active."):setup("Your identity is confirmed. Next, add your authenticator app.");
  };
}
function setup(m){
  step(2);
  app.innerHTML="<h2>Add your authenticator app</h2>"+note(m)+"<p>Open your authenticator app. You can scan a setup image or copy a secret.</p><button class='primary' id='show'>Show secure setup</button>"+help();
  const show=app.querySelector("#show");show.onclick=provision;
}
async function provision(){
  const x=await api("/api/provision");if(!x.r.ok){app.insertAdjacentHTML("afterbegin",note(x.d.message,"bad"));return}
  s=x.d.secret;uri=x.d.uri;log("Authenticator provisioning simulation completed.");if(x.d.verificationCode)log("Mock TOTP test value:",x.d.verificationCode);
  step(2);
  app.innerHTML="<h2>Your setup is ready</h2>"+note(x.d.message)+"<p>Scan this setup image with your authenticator app. You can also copy the secret or setup link.</p><canvas id='qr' class='qr' aria-label='Scannable authenticator setup QR code'></canvas><div class='secret'>"+esc(s)+"</div><div class='row'><button class='secondary' id='copy-secret'>Copy secret</button><button class='secondary' id='uri-link'>Show setup link</button></div><div id='full' hidden class='secret'>"+esc(uri)+"</div><button class='secondary' id='copy-uri' hidden>Copy setup link</button><button class='primary' id='authenticator-added'>I added it to my app</button><div id='msg' class='hint'></div>"+help();
  const qr=app.querySelector("#qr"),copySecret=app.querySelector("#copy-secret"),uriLink=app.querySelector("#uri-link"),full=app.querySelector("#full"),copyUri=app.querySelector("#copy-uri"),authenticatorAdded=app.querySelector("#authenticator-added");
  try{renderQR(qr,uri)}catch{message("The setup image could not be shown. Please copy the secret or setup link instead.")}
  copySecret.onclick=function(){copyText(s,"Authenticator secret")};
  uriLink.onclick=function(){full.hidden=!full.hidden;copyUri.hidden=full.hidden;uriLink.textContent=full.hidden?"Show setup link":"Hide setup link"};
  copyUri.onclick=function(){copyText(uri,"Setup link")};
  authenticatorAdded.onclick=verify;
}
function verify(){
  step(3);
  app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your authenticator app.</p><label for='otp'>Six-digit code</label><input id='otp' inputmode='numeric' autocomplete='one-time-code' maxlength='6' placeholder='123456'><p class='hint'>Example: 123456. You have plenty of time.</p><button class='primary' id='otp-check'>Verify code</button>"+help();
  const otp=app.querySelector("#otp"),otpCheck=app.querySelector("#otp-check");
  otpCheck.onclick=async function(){
    const x=await api("/api/verify-otp",{otp:otp.value.trim()});if(!x.r.ok){app.insertAdjacentHTML("afterbegin",note(x.d.message,"bad"));return}
    backup=x.d.codes;log("Authenticator verification simulation succeeded.");if(x.d.testCodes)log("Mock recovery codes:",x.d.testCodes);save("Your authenticator is now connected.");
  };
}
function save(m){
  step(4);
  app.innerHTML="<h2>Save your recovery codes</h2>"+note(m,"success")+"<p>Store these somewhere safe. Each code works once.</p><div class='codes'>"+backup.map(function(x){return "<div class='code'>"+esc(x)+"</div>"}).join("")+"</div><button class='secondary' id='copy-all'>Copy all recovery codes</button><div id='msg' class='hint'></div><button class='primary' id='saved'>I saved my codes</button>"+help();
  const copyAll=app.querySelector("#copy-all"),saved=app.querySelector("#saved");
  copyAll.onclick=function(){copyText(backup.join("\\n"),"All recovery codes")};
  saved.onclick=function(){account("Your recovery codes are saved.")};
}
function account(m){
  step(4);
  app.innerHTML="<h2>Security setup</h2>"+note(m,"success")+"<p>Your authenticator is active.</p><button class='primary' id='recovery-code'>Use a recovery code</button><button class='secondary' id='replace'>Replace authenticator</button><button class='secondary' id='regenerate'>Generate new recovery codes</button><button class='secondary' id='signout'>Sign out</button>"+help();
  const recoveryCode=app.querySelector("#recovery-code"),replace=app.querySelector("#replace"),regenerate=app.querySelector("#regenerate"),signout=app.querySelector("#signout");
  recoveryCode.onclick=recovery;
  replace.onclick=async function(){const x=await api("/api/begin-reenrolment");x.r.ok?setup("Replacement started. Your current authenticator remains active until checked."):account(x.d.message)};
  regenerate.onclick=async function(){const x=await api("/api/regenerate-backup-codes");if(x.r.ok){backup=x.d.codes;log("Recovery-code generation simulation completed.");save("New recovery codes replaced the old ones.")}else account(x.d.message)};
  signout.onclick=async function(){await api("/api/logout");csrf="";log("Sign-out simulation completed.");signin("You have signed out safely.")};
}
function recovery(m="",k=""){
  step(4);
  app.innerHTML="<h2>Use a recovery code</h2>"+(m?note(m,k):"")+"<p>Use one saved recovery code when you need to check that it works.</p><label for='rc'>Recovery code</label><input id='rc' autocomplete='one-time-code' maxlength='11' placeholder='AAAAA-BBBBB'><p class='hint'>Example: AAAAA-BBBBB</p><button class='primary' id='verify-recovery-code'>Verify recovery code</button><button class='secondary' id='back'>Back to security setup</button>"+help();
  const rc=app.querySelector("#rc"),back=app.querySelector("#back"),verifyRecoveryCode=app.querySelector("#verify-recovery-code");
  rc.oninput=function(){rc.value=rc.value.toUpperCase().replace(/[^A-Z0-9-]/g,"").slice(0,11)};
  back.onclick=function(){account("Your authenticator is active.")};
  verifyRecoveryCode.onclick=async function(){const x=await api("/api/verify-recovery-code",{code:rc.value.trim()});if(x.r.ok)log("Recovery-code verification simulation succeeded.");recovery(x.d.message,x.r.ok?"success":"bad")};
}
signin();
</script></body></html>`;}

Bun.serve({
  hostname:"localhost",
  port:Number(Bun.env.PORT||3000),
  tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
  async fetch(request){try{return await handle(request);}catch{return new Response("Something went wrong. Please try again.",{status:500,headers:secureHeaders(request)});}}
});
console.log("MFA HTTPS server running at https://localhost:"+(Bun.env.PORT||3000));
