
/*
 MFA Enrolment System
 Requirements 1: MFA API routes use the authenticated Marcus session only and CSRF/origin checks.
 Requirements 2: TLS-only serving, secure headers, strict cookies, generic errors, no permissive CORS.
 Requirements 3: cryptographic random values, encrypted OTP secret, salted slow-KDF recovery codes.
 Requirements 4: validated inputs and contextual browser output encoding.
 Requirements 5: rotated sessions, time-based OTPs, single-use recovery codes, rate limiting and lockouts.
*/

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Session = {
  userId: "marcus-account";
  csrf: string;
  created: number;
  lastSeen: number;
};

type RecoveryRecord = { salt: string; derived: string; consumed: boolean };

type MfaState = {
  encryptedSecret?: string;
  verified: boolean;
  recoveryCodes: RecoveryRecord[];
  usedTotpCounters: Set<string>;
  failedAttempts: number;
  lockedUntil: number;
  recoveryFailedAttempts: number;
  recoveryLockedUntil: number;
  mockOtpHash?: string;
  mockOtpIssuedAt?: number;
  mockOtpUsed: boolean;
};

type FailedAttemptRecord = {
  failures: number;
  lockedUntil: number;
  expiresAt: number;
};

const sessions = new Map<string, Session>();
const mfaStates = new Map<string, MfaState>();
const loginFailures = new Map<string, FailedAttemptRecord>();

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const LOCKOUT_MS = 5 * 60_000;
const ATTEMPT_EXPIRY_MS = 20 * 60_000;
const MOCK_OTP_LIFETIME_MS = 10 * 60_000;
const MAX_FAILED_ATTEMPTS = 5;
const TRUSTED_ORIGIN = "https://localhost:3000";
const MOCK_OTP = "654321"; // Deterministic test-only code, returned only in the authenticated provision response.
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

let server: ReturnType<typeof Bun.serve> | undefined;

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function base32Secret(bytes = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = crypto.getRandomValues(new Uint8Array(bytes));
  let bits = 0, value = 0, output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const values = crypto.getRandomValues(new Uint8Array(12));
  let value = "";
  for (const byte of values) value += alphabet[byte % alphabet.length];
  return value.slice(0, 4) + "-" + value.slice(4, 8) + "-" + value.slice(8, 12);
}

function recoveryCodes(): string[] {
  return Array.from({ length: 8 }, recoveryCode);
}

function secureCookie(name: string, value: string, maxAge?: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${
    maxAge === undefined ? "" : `; Max-Age=${maxAge}`
  }`;
}

/* Requirement 2: a fresh CSP nonce is generated for every HTML response. */
function securityHeaders(extra: Record<string, string> = {}, nonce?: string): Record<string, string> {
  const policy = nonce
    ? `default-src 'self'; style-src 'self' 'nonce-${nonce}'; script-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  return {
    "Content-Security-Policy": policy,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}

function apiResponse(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({ "Content-Type": "application/json; charset=utf-8", ...extra }),
  });
}

function cookieValue(request: Request, name: string): string | undefined {
  const found = (request.headers.get("cookie") || "").split(";").map((part) => part.trim())
    .find((part) => part.startsWith(name + "="));
  return found?.slice(name.length + 1);
}

function trustedOrigin(request: Request): boolean {
  return request.headers.get("origin") === TRUSTED_ORIGIN;
}

function requireSession(request: Request): { id: string; session: Session } | null {
  const id = cookieValue(request, "sid");
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!id || !session || now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return { id, session };
}

function csrfIsValid(request: Request, session: Session): boolean {
  return trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}

async function requestBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function getState(userId: string): MfaState {
  let state = mfaStates.get(userId);
  if (!state) {
    state = {
      verified: false,
      recoveryCodes: [],
      usedTotpCounters: new Set(),
      failedAttempts: 0,
      lockedUntil: 0,
      recoveryFailedAttempts: 0,
      recoveryLockedUntil: 0,
      mockOtpUsed: false,
    };
    mfaStates.set(userId, state);
  }
  return state;
}

function clientIp(request: Request): string {
  try {
    return server?.requestIP(request)?.address || "unknown-client";
  } catch {
    return "unknown-client";
  }
}

async function loginAttemptKey(request: Request): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`marcus-account\u0000${clientIp(request)}`),
  );
  return Buffer.from(bytes).toString("base64url");
}

function cleanupFailedAttempts(now = Date.now()): void {
  for (const [key, record] of loginFailures) {
    if (record.expiresAt <= now && record.lockedUntil <= now) loginFailures.delete(key);
  }
}

function loginIsLocked(key: string, now: number): boolean {
  const record = loginFailures.get(key);
  if (!record) return false;
  if (record.expiresAt <= now && record.lockedUntil <= now) {
    loginFailures.delete(key);
    return false;
  }
  return record.lockedUntil > now;
}

function recordLoginFailure(key: string, now: number): void {
  const record = loginFailures.get(key) || { failures: 0, lockedUntil: 0, expiresAt: now + ATTEMPT_EXPIRY_MS };
  record.failures++;
  record.expiresAt = now + ATTEMPT_EXPIRY_MS;
  if (record.failures >= MAX_FAILED_ATTEMPTS) {
    record.failures = 0;
    record.lockedUntil = now + LOCKOUT_MS;
  }
  loginFailures.set(key, record);
}

/* Requirement 3: AES-GCM protects the in-memory OTP shared secret at rest. */
async function encryptAtRest(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(cipher).toString("base64url");
}

async function decryptAtRest(value: string): Promise<string> {
  const [iv, cipher] = value.split(".");
  if (!iv || !cipher) throw new Error("invalid encrypted secret");
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    key,
    Buffer.from(cipher, "base64url"),
  );
  return decoder.decode(plain);
}

async function digestValue(value: string): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString("base64url");
}

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const position = alphabet.indexOf(char);
    if (position < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | position;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function totpForCounter(secret: string, counter: bigint): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const bytes = new Uint8Array(8);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(counter & 255n);
    counter >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = digest[digest.length - 1] & 15;
  const code = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

async function deriveRecovery(value: string, salt: string): Promise<string> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(value), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: Buffer.from(salt, "base64url"), iterations: 150_000, hash: "SHA-256" },
    material,
    256,
  );
  return Buffer.from(bits).toString("base64url");
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left), b = encoder.encode(right);
  let difference = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index++) difference |= (a[index] || 0) ^ (b[index] || 0);
  return difference === 0;
}

async function createRecoveryRecords(codes: string[]): Promise<RecoveryRecord[]> {
  return Promise.all(codes.map(async (code) => {
    const salt = randomToken(16);
    return { salt, derived: await deriveRecovery(code, salt), consumed: false };
  }));
}

function pageHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank MFA</title>
<style nonce="${nonce}">
:root{font-family:Verdana,Arial,sans-serif;color:#14213d;background:#f3f7fb;letter-spacing:.035em;line-height:1.65}*{box-sizing:border-box}body{margin:0}.wrap{max-width:540px;margin:auto;padding:18px}.brand{font-weight:bold;color:#174c88}.card{background:#fff;border-radius:16px;padding:22px;box-shadow:0 2px 13px #14213d1a;margin:13px 0}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:9px 0}.step{font-weight:bold;color:#315b96}.icon{font-size:2rem}label{display:block;font-weight:bold;margin-top:15px}small{display:block;color:#405169;font-weight:normal;font-size:.88rem}input,textarea{width:100%;min-height:51px;border:2px solid #62748b;border-radius:9px;padding:10px;font:inherit;font-size:1rem;margin-top:5px}textarea{resize:vertical;line-height:1.5}.code{letter-spacing:.16em;font-size:1.16rem}button{width:100%;min-height:51px;border:0;border-radius:9px;background:#075bb5;color:#fff;font:inherit;font-weight:bold;margin-top:16px;padding:10px;cursor:pointer}button.secondary{background:#fff;color:#075bb5;border:2px solid #075bb5;margin-top:9px}button:focus,input:focus,textarea:focus{outline:3px solid #e49b24;outline-offset:2px}.hint,.error,.notice{padding:12px;border-radius:9px;margin-top:16px}.hint{background:#edf4ff}.error{background:#ffe9e9;color:#761b1b}.notice{background:#e7f7ed}.secret,.codes{background:#f1f5f9;border-radius:9px;padding:13px;overflow-wrap:anywhere;line-height:1.9}.qr{width:294px;height:294px;max-width:100%;display:block;margin:12px auto;image-rendering:pixelated;background:#fff}.manual{margin-top:13px}@media(max-width:390px){.wrap{padding:12px}.card{padding:18px}h1{font-size:1.38rem}}
</style>
</head>
<body>
<main class="wrap">
<p class="brand">SecureBank · account protection</p>
<section class="card" id="app" aria-live="polite"></section>
</main>
<script nonce="${nonce}">
(function(){
var csrf="",secret="",uri="",mockOtp="",visible=false;
var app=document.getElementById("app");
function esc(v){return String(v).replace(/[&<>"']/g,function(c){return({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]})}
/* Test values are intentionally written only to the browser console, never to a page log. */
function log(message){console.log(message)}
async function api(path,method,data){var r=await fetch(path,{method:method||"GET",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:data===undefined?undefined:JSON.stringify(data)});var p;try{p=await r.json()}catch(_){throw Error("Something went wrong. Please try again.")}if(!r.ok)throw Error(p.error||"Something went wrong. Please try again.");return p}
function hint(){return '<aside class="hint"><strong>💡 Need help?</strong><br>You can retry safely. There is no reading deadline.</aside>'}
function announce(message){var x=document.getElementById("copy-msg");if(x)x.textContent=message}
function selectFallback(id,message){var field=document.getElementById(id);if(field){field.focus();field.select();if(field.setSelectionRange)field.setSelectionRange(0,field.value.length)}announce(message)}
function copy(text,fallbackId,label){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(function(){announce(label+" copied. You can paste it where you need it.")}).catch(function(){selectFallback(fallbackId,"Copy was not available. The "+label.toLowerCase()+" is selected below. Use your browser copy control.")})}else selectFallback(fallbackId,"Copy was not available. The "+label.toLowerCase()+" is selected below. Use your browser copy control.")}
function hintManual(label,id,value,rows){return '<div class="manual"><label for="'+id+'">'+label+' <small>Select this text and use your browser copy control if the Copy button does not work.</small></label><textarea id="'+id+'" readonly spellcheck="false" rows="'+(rows||2)+'">'+esc(value)+'</textarea></div>'}

/* QR Model 2 version 7-L byte encoder. The byte mode indicator is explicitly 0100.
   qrDecode verifies the rendered module matrix round-trips to the exact provisioning URI. */
function qrBytes(text){var a=[];for(var i=0;i<text.length;i++)a.push(text.charCodeAt(i));return a}
function gfMul(a,b){var z=0;while(b){if(b&1)z^=a;a=a&128?(a<<1)^285:a<<1;b>>=1}return z}
function rs(data,n){var gen=[1],i,j;for(i=0;i<n;i++){var next=Array(gen.length+1).fill(0),p=1;for(j=0;j<i;j++)p=gfMul(p,2);for(j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=gfMul(gen[j],p)}gen=next}var out=Array(n).fill(0);for(i=0;i<data.length;i++){var f=data[i]^out.shift();out.push(0);for(j=0;j<n;j++)out[j]^=gfMul(gen[j+1],f)}return out}
function bch(v,g){function len(n){var q=0;while(n){q++;n>>=1}return q}var d=len(g);v<<=d-1;while(len(v)>=d)v^=g<<(len(v)-d);return v}
function qrMatrix(text){
 var n=45,m=Array.from({length:n},function(){return Array(n).fill(null)}),reserved=Array.from({length:n},function(){return Array(n).fill(false)}),bits=[],raw=qrBytes(text),i,j,x,y;
 function put(x,y,v){if(x>=0&&y>=0&&x<n&&y<n){m[y][x]=v;reserved[y][x]=true}}
 function finder(x,y){for(var yy=-1;yy<=7;yy++)for(var xx=-1;xx<=7;xx++)put(x+xx,y+yy,xx>=0&&xx<=6&&yy>=0&&yy<=6&&(xx===0||xx===6||yy===0||yy===6||(xx>=2&&xx<=4&&yy>=2&&yy<=4)))}
 function align(x,y){for(var yy=-2;yy<=2;yy++)for(var xx=-2;xx<=2;xx++)put(x+xx,y+yy,Math.max(Math.abs(xx),Math.abs(yy))!==1)}
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(i=8;i<n-8;i++){put(i,6,i%2===0);put(6,i,i%2===0)}
 [6,22,38].forEach(function(a){[6,22,38].forEach(function(c){if(!((a===6&&c===6)||(a===6&&c===38)||(a===38&&c===6)))align(a,c)})});
 put(8,n-8,true);
 var vd=(7<<12)|bch(7,0x1f25);for(i=0;i<18;i++){var vb=((vd>>i)&1)===1;put(n-11+i%3,Math.floor(i/3),vb);put(Math.floor(i/3),n-11+i%3,vb)}
 bits.push(0,1,0,0);
 for(i=7;i>=0;i--)bits.push((raw.length>>i)&1);
 raw.forEach(function(v){for(var q=7;q>=0;q--)bits.push((v>>q)&1)});
 for(i=0;i<4;i++)bits.push(0);while(bits.length%8)bits.push(0);
 var data=[];for(i=0;i<bits.length;i+=8){var z=0;for(j=0;j<8;j++)z=(z<<1)|bits[i+j];data.push(z)}
 for(i=0;data.length<156;i++)data.push(i%2?17:236);
 var blocks=[data.slice(0,78),data.slice(78)],ecc=[rs(blocks[0],20),rs(blocks[1],20)],words=[];
 for(i=0;i<78;i++)words.push(blocks[0][i],blocks[1][i]);
 for(i=0;i<20;i++)words.push(ecc[0][i],ecc[1][i]);
 bits=[];words.forEach(function(v){for(var q=7;q>=0;q--)bits.push((v>>q)&1)});
 var k=0,up=true;
 for(x=n-1;x>0;x-=2){if(x===6)x--;for(var t=0;t<n;t++){y=up?n-1-t:t;for(j=0;j<2;j++){var xx=x-j;if(!reserved[y][xx]){var bit=k<bits.length?bits[k++]:0;m[y][xx]=((xx+y)%2===0)?!bit:!!bit}}}up=!up}
 var fd=(1<<13)|bch(8,0x537);fd^=0x5412;function fb(q){return ((fd>>q)&1)===1}
 for(i=0;i<=5;i++)put(8,i,fb(i));put(8,7,fb(6));put(8,8,fb(7));put(7,8,fb(8));for(i=9;i<15;i++)put(14-i,8,fb(i));
 for(i=0;i<8;i++)put(n-1-i,8,fb(i));for(i=8;i<15;i++)put(8,n-15+i,fb(i));
 return {m:m,reserved:reserved}
}
function qrDecode(q){
 var n=45,bits=[],x,y,j,k=0,up=true;
 for(x=n-1;x>0;x-=2){if(x===6)x--;for(var t=0;t<n;t++){y=up?n-1-t:t;for(j=0;j<2;j++){var xx=x-j;if(!q.reserved[y][xx]){var bit=q.m[y][xx]?1:0;if((xx+y)%2===0)bit^=1;bits.push(bit)}}}up=!up}
 var words=[];for(k=0;k<196;k++){var v=0;for(j=0;j<8;j++)v=(v<<1)|(bits[k*8+j]||0);words.push(v)}
 var data=[];for(k=0;k<78;k++){data.push(words[k*2],words[k*2+1])}
 function take(count){var v=0;for(var a=0;a<count;a++)v=(v<<1)|dataBits.shift();return v}
 var dataBits=[];data.forEach(function(v){for(var a=7;a>=0;a--)dataBits.push((v>>a)&1)});
 if(take(4)!==4)return "";
 var length=take(8),out="";for(k=0;k<length;k++)out+=String.fromCharCode(take(8));
 return out
}
function drawQr(text){var c=document.getElementById("qr");if(!c)return;var q=qrMatrix(text);if(qrDecode(q)!==text)throw Error("QR setup image could not be checked.");var scale=6,quiet=4;c.width=c.height=(45+quiet*2)*scale;var g=c.getContext("2d");g.fillStyle="#fff";g.fillRect(0,0,c.width,c.height);g.fillStyle="#14213d";for(var y=0;y<45;y++)for(var x=0;x<45;x++)if(q.m[y][x])g.fillRect((x+quiet)*scale,(y+quiet)*scale,scale,scale)}
function error(message,retry){app.innerHTML='<div class="icon">⚠️</div><h1>Please check that</h1><p class="error">'+esc(message)+'</p><button id="retry">Try again</button>'+hint();document.getElementById("retry").onclick=retry||identity}
function identity(){app.innerHTML='<p class="step">Step 1 of 4</p><div class="icon">🪪</div><h1>Confirm it is you</h1><p>Enter the two details from your account opening.</p><label for="dob">Date of birth <small>Example: 14 June 1971</small></label><input id="dob" autocomplete="bday" placeholder="14 June 1971"><label for="end">Last four account digits <small>Example: 4821</small></label><input id="end" inputmode="numeric" maxlength="4" placeholder="4821"><button id="go">Confirm identity</button>'+hint();document.getElementById("go").onclick=async function(){try{var r=await api("/api/login","POST",{dateOfBirth:document.getElementById("dob").value,accountEnding:document.getElementById("end").value});csrf=r.csrf;log("Mock identity verification confirmed for Marcus. Starting MFA enrolment.");setup()}catch(e){error(e.message,identity)}}}
function renderSetup(message){
 var material=visible?'<canvas class="qr" id="qr" role="img" aria-label="QR code for SecureBank authenticator setup"></canvas><p class="secret">'+esc(secret)+'</p><button class="secondary" id="copy">Copy setup key</button><button class="secondary" id="link">Copy setup link</button>'+hintManual("Setup key","manual-key",secret,2)+hintManual("Setup link","manual-uri",uri,3):'<p class="notice">Your setup details are hidden. Reveal them when you are ready to scan or copy them.</p>';
 app.innerHTML='<p class="step">Step 2 of 4</p><div class="icon">📱</div><h1>Add your authenticator</h1><p>Reveal the setup details, then scan the QR code or copy the setup key.</p>'+(message?'<p class="notice">'+esc(message)+'</p>':"")+material+'<button class="secondary" id="reveal">'+(visible?"Hide":"Reveal")+" setup details</button><button class="secondary" id="restart">Start setup again</button><p id="copy-msg" role="status" aria-live="polite"></p><label for="otp">Enter the 6-digit code from your app <small>Example: 123456</small></label><input class="code" id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6"><button id="verify">Verify code</button>'+hint();
 if(visible){drawQr(uri);document.getElementById("copy").onclick=function(){copy(secret,"manual-key","Setup key")};document.getElementById("link").onclick=function(){copy(uri,"manual-uri","Setup link")}}
 document.getElementById("reveal").onclick=function(){visible=!visible;renderSetup()};
 document.getElementById("restart").onclick=function(){setup("New setup details are ready. Your previous unverified setup details have been replaced.")};
 document.getElementById("verify").onclick=async function(){try{await api("/api/mfa/verify","POST",{otp:document.getElementById("otp").value});log("Mock authenticator code verified.");codes()}catch(e){renderSetup(e.message)}}
}
async function setup(message){try{secret="";uri="";mockOtp="";visible=false;var r=await api("/api/mfa/provision","POST",{});secret=r.secret;uri=r.provisioningUri;mockOtp=r.mockOtp;log("Mock OTP issued: "+mockOtp);renderSetup(message)}catch(e){error(e.message,identity)}}
function codeScreen(list){var joined=list.join("\\n");app.innerHTML='<p class="step">Step 3 of 4</p><div class="icon">🧾</div><h1>Save your recovery codes</h1><p>Keep these somewhere safe. Each code works once.</p><div class="codes">'+list.map(esc).join("<br>")+'</div><button class="secondary" id="copycodes">Copy recovery codes</button>'+hintManual("Recovery codes","manual-codes",joined,8)+'<p id="copy-msg" role="status" aria-live="polite"></p><button id="done">I have saved them</button>'+hint();document.getElementById("copycodes").onclick=function(){copy(joined,"manual-codes","Recovery codes")};document.getElementById("done").onclick=complete}
async function codes(){try{var r=await api("/api/mfa/backup-codes","POST",{});log("Recovery codes issued: "+r.codes.join(", "));codeScreen(r.codes)}catch(e){error(e.message,renderSetup)}}
function complete(){app.innerHTML='<p class="step">Step 4 of 4</p><div class="icon">✅</div><h1>MFA is ready</h1><p>Your authenticator is set up and recovery codes have been shown.</p><p class="notice"><strong>What happens next:</strong><br>Use your authenticator when asked to confirm a payment.</p><button id="out">Sign out</button><button class="secondary" id="manage">Recovery code options</button>';document.getElementById("out").onclick=out;document.getElementById("manage").onclick=options}
function options(){app.innerHTML='<div class="icon">🧾</div><h1>Recovery code options</h1><p>You can test a recovery code or make a replacement set.</p><button id="use">Use a recovery code</button><button class="secondary" id="new">Regenerate recovery codes</button><button class="secondary" id="back">Back</button>'+hint();document.getElementById("use").onclick=use;document.getElementById("new").onclick=async function(){try{var r=await api("/api/mfa/backup-codes/regenerate","POST",{});log("Replacement recovery codes issued: "+r.codes.join(", "));codeScreen(r.codes)}catch(e){error(e.message,options)}};document.getElementById("back").onclick=complete}
function use(message){app.innerHTML='<div class="icon">🔑</div><h1>Use a recovery code</h1><p>Enter one saved recovery code. It will work once.</p>'+(message?'<p class="error">'+esc(message)+'</p>':"")+'<label for="rc">Recovery code <small>Example: ABCD-EFGH-JKLM</small></label><input id="rc" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCD-EFGH-JKLM"><button id="check">Use recovery code</button><button class="secondary" id="back">Back</button>'+hint();document.getElementById("back").onclick=options;document.getElementById("check").onclick=async function(){try{await api("/api/mfa/recovery/verify","POST",{code:document.getElementById("rc").value});app.innerHTML='<div class="icon">✅</div><h1>Recovery code accepted</h1><p>This recovery code has now been used and cannot be used again.</p><button id="done">Done</button>';document.getElementById("done").onclick=complete}catch(e){use(e.message)}}}
async function out(){try{await api("/api/logout","POST",{})}catch(_){}csrf="";secret="";uri="";mockOtp="";log("Signed out. Session removed.");identity()}
identity();
}());
</script>
</body>
</html>`;
}

const certificate = Bun.file("certs/cert.pem");
const privateKey = Bun.file("certs/key.pem");

if (!(await certificate.exists()) || !(await privateKey.exists())) {
  console.error("Secure server could not start.");
  process.exit(1);
}

try {
  server = Bun.serve({
    port: 3000,
    tls: { cert: certificate, key: privateKey },
    fetch: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "GET" && path === "/") {
        const nonce = randomToken(24);
        return new Response(pageHtml(nonce), {
          headers: securityHeaders({ "Content-Type": "text/html; charset=utf-8" }, nonce),
        });
      }

      if (request.method === "POST" && path === "/api/login") {
        if (!trustedOrigin(request)) {
          return apiResponse({ error: "Please use the SecureBank page to continue." }, 403);
        }
        cleanupFailedAttempts();
        const input = await requestBody(request);
        const dob = typeof input.dateOfBirth === "string" ? input.dateOfBirth.trim().replace(/\s+/g, " ") : "";
        const ending = typeof input.accountEnding === "string" ? input.accountEnding.trim() : "";
        const key = await loginAttemptKey(request);
        const now = Date.now();

        if (loginIsLocked(key, now)) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }
        if (!(/^(14 june 1971|14\/06\/1971|1971-06-14)$/i.test(dob) && ending === "4821")) {
          recordLoginFailure(key, now);
          return apiResponse({ error: "We could not confirm those details. Check them and try again." }, 400);
        }

        loginFailures.delete(key);
        const oldSid = cookieValue(request, "sid");
        if (oldSid) sessions.delete(oldSid);
        const sid = randomToken(), csrf = randomToken();
        sessions.set(sid, { userId: "marcus-account", csrf, created: now, lastSeen: now });
        return apiResponse({ csrf }, 200, {
          "Set-Cookie": secureCookie("sid", sid, Math.floor(SESSION_ABSOLUTE_MS / 1000)),
        });
      }

      const authenticated = requireSession(request);
      if (!authenticated) {
        return apiResponse({ error: "Your session ended. Please sign in again." }, 401, {
          "Set-Cookie": secureCookie("sid", "", 0),
        });
      }

      if (request.method !== "GET" && !csrfIsValid(request, authenticated.session)) {
        return apiResponse({ error: "Your secure form token was missing. Please try again." }, 403);
      }

      /* Requirement 1: no endpoint accepts a user ID; authenticated owner exclusively selects state. */
      const state = getState(authenticated.session.userId);

      if (request.method === "POST" && path === "/api/mfa/provision") {
        const now = Date.now();
        if (now < state.lockedUntil) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        const secret = base32Secret(20);
        state.encryptedSecret = await encryptAtRest(secret);
        state.verified = false;
        state.recoveryCodes = [];
        state.usedTotpCounters.clear();
        state.mockOtpHash = await digestValue(MOCK_OTP);
        state.mockOtpIssuedAt = now;
        state.mockOtpUsed = false;

        const provisioningUri = "otpauth://totp/" + encodeURIComponent("SecureBank:Marcus") +
          "?secret=" + secret + "&issuer=SecureBank&algorithm=SHA1&digits=6&period=30";

        /* No server log contains this response's secret, URI, OTP, or recovery data. */
        return apiResponse({ secret, provisioningUri, mockOtp: MOCK_OTP });
      }

      if (request.method === "POST" && path === "/api/mfa/verify") {
        const input = await requestBody(request);
        const otp = typeof input.otp === "string" ? input.otp.trim() : "";
        const now = Date.now();

        if (now < state.lockedUntil) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        let matched: bigint | null = null;
        let acceptedMock = false;

        if (/^\d{6}$/.test(otp) && state.encryptedSecret) {
          const canUseMock = !state.mockOtpUsed && !!state.mockOtpHash && !!state.mockOtpIssuedAt &&
            now - state.mockOtpIssuedAt <= MOCK_OTP_LIFETIME_MS;
          if (canUseMock && constantTimeEqual(await digestValue(otp), state.mockOtpHash!)) {
            acceptedMock = true;
          } else {
            const secret = await decryptAtRest(state.encryptedSecret);
            const current = BigInt(Math.floor(now / 30_000));
            for (const offset of [-1n, 0n, 1n]) {
              const counter = current + offset;
              if (constantTimeEqual(otp, await totpForCounter(secret, counter)) &&
                !state.usedTotpCounters.has(counter.toString())) {
                matched = counter;
                break;
              }
            }
          }
        }

        if (!acceptedMock && matched === null) {
          state.failedAttempts++;
          if (state.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            state.failedAttempts = 0;
            state.lockedUntil = now + LOCKOUT_MS;
          }
          return apiResponse({
            error: "That code did not work. Check the 6 digits in your authenticator app and try again.",
          }, 400);
        }

        if (matched !== null) state.usedTotpCounters.add(matched.toString());
        state.mockOtpUsed = true;
        state.failedAttempts = 0;
        state.verified = true;
        return apiResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/api/mfa/backup-codes") {
        if (!state.encryptedSecret || !state.verified) {
          return apiResponse({ error: "Verify your authenticator code before creating recovery codes." }, 400);
        }
        if (state.recoveryCodes.length) {
          return apiResponse({ error: "Your recovery codes already exist. Use Recovery code options to replace them." }, 400);
        }
        const codes = recoveryCodes();
        state.recoveryCodes = await createRecoveryRecords(codes);
        return apiResponse({ codes });
      }

      if (request.method === "POST" && path === "/api/mfa/backup-codes/regenerate") {
        if (!state.encryptedSecret || !state.verified) {
          return apiResponse({ error: "Verify your authenticator before replacing recovery codes." }, 400);
        }
        const codes = recoveryCodes();
        state.recoveryCodes = await createRecoveryRecords(codes);
        return apiResponse({ codes });
      }

      if (request.method === "POST" && path === "/api/mfa/recovery/verify") {
        const now = Date.now();
        if (now < state.recoveryLockedUntil) {
          return apiResponse({ error: "Too many recovery code attempts. Please wait a few minutes, then try again." }, 429);
        }

        const input = await requestBody(request);
        const code = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
        const failedRecovery = (): Response => {
          state.recoveryFailedAttempts++;
          if (state.recoveryFailedAttempts >= MAX_FAILED_ATTEMPTS) {
            state.recoveryFailedAttempts = 0;
            state.recoveryLockedUntil = now + LOCKOUT_MS;
          }
          return apiResponse({ error: "That recovery code did not work. Check the code and try another saved code." }, 400);
        };

        if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) {
          failedRecovery();
          return apiResponse({ error: "Enter a recovery code in the example format: ABCD-EFGH-JKLM." }, 400);
        }

        let match: RecoveryRecord | undefined;
        for (const record of state.recoveryCodes) {
          if (record.consumed) continue;
          if (constantTimeEqual(await deriveRecovery(code, record.salt), record.derived)) {
            match = record;
            break;
          }
        }
        if (!match) return failedRecovery();

        match.consumed = true;
        state.recoveryFailedAttempts = 0;
        state.recoveryLockedUntil = 0;
        return apiResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/api/logout") {
        sessions.delete(authenticated.id);
        return apiResponse({ ok: true }, 200, { "Set-Cookie": secureCookie("sid", "", 0) });
      }

      return apiResponse({ error: "Page not found." }, 404);
    },
    error() {
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    },
  });

  console.log(`Secure MFA app running at https://localhost:${server.port}`);
} catch {
  console.error("Secure server could not start.");
  process.exit(1);
}
