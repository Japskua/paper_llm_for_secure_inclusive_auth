
/*
 MFA Enrolment System
 Requirements 1: MFA API routes use the authenticated Marcus session only and CSRF/origin checks.
 Requirements 2: TLS-only serving, secure headers, strict cookies, generic errors, no permissive CORS.
 Requirements 3: cryptographic random values, encrypted OTP secret, salted slow-KDF recovery codes.
 Requirements 4: validated inputs and contextual browser output encoding.
 Requirements 5: rotated sessions, real time-based OTPs, single-use recovery codes, rate limiting.
*/

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Session = {
  userId: "marcus-account";
  csrf: string;
  created: number;
  lastSeen: number;
};

type RecoveryRecord = {
  salt: string;
  derived: string;
  consumed: boolean;
};

type MfaState = {
  encryptedSecret?: string;
  verified: boolean;
  recoveryCodes: RecoveryRecord[];
  usedTotpCounters: Set<string>;
  failedAttempts: number;
  lockedUntil: number;
};

const sessions = new Map<string, Session>();
const mfaStates = new Map<string, MfaState>();

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const LOCKOUT_MS = 5 * 60_000;
const TRUSTED_ORIGIN = "https://localhost:3000";
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function base32Secret(bytes = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = crypto.getRandomValues(new Uint8Array(bytes));
  let bits = 0;
  let value = 0;
  let output = "";
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
  const random = crypto.getRandomValues(new Uint8Array(12));
  let value = "";
  for (const byte of random) value += alphabet[byte % alphabet.length];
  return value.slice(0, 4) + "-" + value.slice(4, 8) + "-" + value.slice(8, 12);
}

function recoveryCodes(): string[] {
  return Array.from({ length: 8 }, recoveryCode);
}

function secureCookie(name: string, value: string, maxAge?: number): string {
  const age = maxAge === undefined ? "" : `; Max-Age=${maxAge}`;
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function securityHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
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
  const match = (request.headers.get("cookie") || "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(name + "="));
  return match?.slice(name.length + 1);
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

function trustedOrigin(request: Request): boolean {
  return request.headers.get("origin") === TRUSTED_ORIGIN;
}

function csrfIsValid(request: Request, session: Session): boolean {
  return trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}

async function requestBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
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
    };
    mfaStates.set(userId, state);
  }
  return state;
}

/* Requirement 3: AES-GCM protects the in-memory OTP shared secret at rest. */
async function encryptAtRest(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(ciphertext).toString("base64url");
}

async function decryptAtRest(value: string): Promise<string> {
  const [ivText, cipherText] = value.split(".");
  if (!ivText || !cipherText) throw new Error("invalid encrypted value");
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    key,
    Buffer.from(cipherText, "base64url"),
  );
  return decoder.decode(plain);
}

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const result: number[] = [];
  for (const character of value.replace(/=+$/g, "").toUpperCase()) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | position;
    bits += 5;
    if (bits >= 8) {
      result.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}

/* Requirement 5: standards-compatible RFC 6238 TOTP calculation (HMAC-SHA-1, 30 seconds). */
async function totpForCounter(secret: string, counter: bigint): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const counterBytes = new Uint8Array(8);
  let number = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(number & 255n);
    number >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = digest[digest.length - 1] & 15;
  const numberCode = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(numberCode % 1_000_000).padStart(6, "0");
}

async function currentTotp(secret: string): Promise<{ code: string; counter: bigint }> {
  const counter = BigInt(Math.floor(Date.now() / 30_000));
  return { code: await totpForCounter(secret, counter), counter };
}

/* Requirement 3: each recovery code receives an independent salt and a slow PBKDF2 KDF. */
async function deriveRecovery(value: string, saltText: string): Promise<string> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(value), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: Buffer.from(saltText, "base64url"), iterations: 150_000, hash: "SHA-256" },
    material,
    256,
  );
  return Buffer.from(bits).toString("base64url");
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) difference |= (a[i % (a.length || 1)] || 0) ^ (b[i % (b.length || 1)] || 0);
  return difference === 0;
}

async function createRecoveryRecords(codes: string[]): Promise<RecoveryRecord[]> {
  return Promise.all(codes.map(async (code) => {
    const salt = randomToken(16);
    return { salt, derived: await deriveRecovery(code, salt), consumed: false };
  }));
}

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank MFA</title>
<style>
:root { font-family: Verdana, Arial, sans-serif; color:#14213d; background:#f3f7fb; letter-spacing:.03em; line-height:1.7; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; }
.wrap { max-width:540px; margin:0 auto; padding:18px; }
.brand { color:#174c88; font-size:.95rem; font-weight:bold; margin:4px 0 14px; }
.card { background:#fff; border-radius:16px; padding:23px; box-shadow:0 2px 13px rgba(20,33,61,.10); }
h1 { font-size:1.55rem; line-height:1.32; margin:0 0 10px; }
h2 { font-size:1.08rem; line-height:1.4; margin:0 0 8px; }
p { margin:10px 0; }
.step { color:#315b96; font-weight:bold; margin:0 0 4px; }
.icon { font-size:2rem; line-height:1.2; margin-bottom:8px; }
label { display:block; font-weight:bold; margin-top:15px; }
small { display:block; font-size:.88rem; font-weight:normal; color:#39495e; letter-spacing:.02em; }
input { width:100%; min-height:51px; margin-top:5px; border:2px solid #62748b; border-radius:9px; padding:10px 12px; color:#14213d; font:inherit; font-size:1rem; background:white; }
input.code-input { letter-spacing:.18em; font-size:1.2rem; }
button { width:100%; min-height:51px; margin-top:17px; padding:11px 14px; cursor:pointer; border:0; border-radius:9px; background:#075bb5; color:white; font:inherit; font-weight:bold; letter-spacing:.025em; }
button.secondary { margin-top:10px; background:white; border:2px solid #075bb5; color:#075bb5; }
button:focus,input:focus,a:focus { outline:3px solid #e49b24; outline-offset:2px; }
.hint,.notice,.error,.warning { margin-top:17px; padding:12px; border-radius:9px; }
.hint { background:#edf4ff; }
.notice { background:#e7f7ed; }
.error { background:#ffe9e9; color:#761b1b; }
.warning { background:#fff4d9; color:#604600; }
.secret,.codes { overflow-wrap:anywhere; background:#f1f5f9; border-radius:9px; padding:13px; font-family:Verdana,Arial,sans-serif; letter-spacing:.07em; }
.codes { line-height:2; }
.qr-wrap { display:flex; justify-content:center; margin:15px 0 7px; }
.qr { width:210px; height:210px; border:10px solid white; background:white; image-rendering:pixelated; }
.muted { color:#48566a; }
.hidden-secret { letter-spacing:.16em; }
@media (max-width:390px) { .wrap { padding:12px; } .card { padding:18px; } h1 { font-size:1.38rem; } }
</style>
</head>
<body>
<main class="wrap">
  <p class="brand">SecureBank · account protection</p>
  <section class="card" id="app" aria-live="polite"></section>
</main>
<script>
/*
 Inclusivity requirements: plain language, predictable four-step flow, generous spacing,
 copy support, no timers on screen, and one prominent action per screen.
 Sensitive mock values are deliberately written only to the browser developer console.
*/
(function () {
  var csrf = "";
  var setupSecret = "";
  var setupUri = "";
  var secretVisible = false;
  var app = document.getElementById("app");

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
    });
  }

  function browserLog(message) { console.log(message); }

  async function api(path, method, data) {
    var response = await fetch(path, {
      method: method || "GET",
      headers: { "Content-Type":"application/json", "X-CSRF-Token":csrf },
      body: data === undefined ? undefined : JSON.stringify(data)
    });
    var payload;
    try { payload = await response.json(); }
    catch (_) { throw new Error("Something went wrong. Please try again."); }
    if (!response.ok) throw new Error(payload.error || "Something went wrong. Please try again.");
    return payload;
  }

  function copyText(text) {
    var message = document.getElementById("copy-message");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        if (message) message.textContent = "Copied. You can paste it where you need it.";
      }).catch(function () {
        if (message) message.textContent = "Please select the text and copy it.";
      });
    } else if (message) message.textContent = "Please select the text and copy it.";
  }

  function help() {
    return '<aside class="hint"><strong>💡 Need help?</strong><br>You can retry safely. There is no reading deadline.</aside>';
  }

  /*
   Self-contained QR encoder: QR Model 2 Version 6, error correction level L.
   The provisioning URI fits its 136-byte byte-mode capacity. It creates finder,
   alignment, timing, BCH format, Reed-Solomon error correction, interleaving,
   all eight masks, and penalty-based mask selection, so scanner apps can read it.
  */
  function qrEncode(text) {
    var bytes = new TextEncoder().encode(text);
    if (bytes.length > 134) throw new Error("Setup link is too long.");
    var size = 41, totalData = 136, ecLength = 18, blocks = 2;
    var data = [];
    function pushBits(value, count) { for (var i=count-1;i>=0;i--) data.push((value >>> i) & 1); }
    pushBits(4,4); pushBits(bytes.length,8);
    for (var bi=0;bi<bytes.length;bi++) pushBits(bytes[bi],8);
    var capacity = totalData * 8;
    for (var t=0;t<4 && data.length<capacity;t++) data.push(0);
    while (data.length % 8) data.push(0);
    var dataBytes = [];
    for (var i=0;i<data.length;i+=8) { var byte=0; for(var j=0;j<8;j++) byte=(byte<<1)|data[i+j]; dataBytes.push(byte); }
    for (var pad=0;dataBytes.length<totalData;pad++) dataBytes.push(pad%2 ? 0x11 : 0xec);

    var exp=[], log=[], x=1;
    for (i=0;i<255;i++) { exp[i]=x; log[x]=i; x<<=1; if(x&256) x^=0x11d; }
    for (i=255;i<512;i++) exp[i]=exp[i-255];
    function multiply(a,b) { return !a || !b ? 0 : exp[log[a]+log[b]]; }
    function ecc(block) {
      var generator=[1];
      for (var n=0;n<ecLength;n++) {
        var next=new Array(generator.length+1).fill(0);
        for(var g=0;g<generator.length;g++) { next[g]^=generator[g]; next[g+1]^=multiply(generator[g],exp[n]); }
        generator=next;
      }
      var rem=new Array(ecLength).fill(0);
      for(var q=0;q<block.length;q++) {
        var factor=block[q]^rem.shift(); rem.push(0);
        for(var r=0;r<ecLength;r++) rem[r]^=multiply(generator[r+1],factor);
      }
      return rem;
    }
    var blockData=[dataBytes.slice(0,68),dataBytes.slice(68,136)];
    var blockEc=[ecc(blockData[0]),ecc(blockData[1])], words=[];
    for(i=0;i<68;i++) for(var b=0;b<blocks;b++) words.push(blockData[b][i]);
    for(i=0;i<ecLength;i++) for(b=0;b<blocks;b++) words.push(blockEc[b][i]);
    var stream=[];
    for(i=0;i<words.length;i++) for(j=7;j>=0;j--) stream.push((words[i]>>>j)&1);

    function emptyMatrix() { return Array.from({length:size},function(){return new Array(size).fill(null);}); }
    function setFinder(m,px,py) {
      for(var yy=-1;yy<=7;yy++) for(var xx=-1;xx<=7;xx++) {
        var X=px+xx,Y=py+yy;
        if(X>=0&&Y>=0&&X<size&&Y<size) m[Y][X]=(xx>=0&&xx<=6&&yy>=0&&yy<=6&&(xx===0||xx===6||yy===0||yy===6||(xx>=2&&xx<=4&&yy>=2&&yy<=4)));
      }
    }
    function baseMatrix() {
      var m=emptyMatrix(); setFinder(m,0,0); setFinder(m,size-7,0); setFinder(m,0,size-7);
      for(var yy=-2;yy<=2;yy++) for(var xx=-2;xx<=2;xx++) m[34+yy][34+xx]=(Math.max(Math.abs(xx),Math.abs(yy))!==1);
      for(i=8;i<size-8;i++) { if(m[6][i]===null)m[6][i]=i%2===0; if(m[i][6]===null)m[i][6]=i%2===0; }
      for(i=0;i<=5;i++) { m[i][8]=false; m[8][i]=false; }
      m[7][8]=false; m[8][7]=false; m[8][8]=false;
      for(i=9;i<=14;i++) { m[8][14-i]=false; m[14-i][8]=false; }
      for(i=0;i<8;i++) m[8][size-1-i]=false;
      for(i=8;i<15;i++) m[size-15+i][8]=false;
      m[size-8][8]=true;
      return m;
    }
    function maskBit(mask,row,col) {
      if(mask===0)return (row+col)%2===0; if(mask===1)return row%2===0;
      if(mask===2)return col%3===0; if(mask===3)return (row+col)%3===0;
      if(mask===4)return (Math.floor(row/2)+Math.floor(col/3))%2===0;
      if(mask===5)return (row*col)%2+(row*col)%3===0;
      if(mask===6)return ((row*col)%2+(row*col)%3)%2===0;
      return ((row+col)%2+(row*col)%3)%2===0;
    }
    function addFormat(m,mask) {
      var bits=((1<<3)|mask)<<10, rem=bits;
      while(Math.floor(Math.log2(rem))>=10) rem^=0x537 << (Math.floor(Math.log2(rem))-10);
      bits=(bits|rem)^0x5412;
      function bit(k){return ((bits>>>k)&1)===1;}
      for(i=0;i<=5;i++)m[i][8]=bit(i);
      m[7][8]=bit(6);m[8][8]=bit(7);m[8][7]=bit(8);
      for(i=9;i<=14;i++)m[8][14-i]=bit(i);
      for(i=0;i<8;i++)m[8][size-1-i]=bit(i);
      for(i=8;i<15;i++)m[size-15+i][8]=bit(i);
    }
    function fill(mask) {
      var m=baseMatrix(), index=0, upward=true;
      for(var right=size-1;right>0;right-=2) {
        if(right===6) right--;
        for(var step=0;step<size;step++) {
          var row=upward ? size-1-step : step;
          for(var c=0;c<2;c++) { var col=right-c; if(m[row][col]===null) { var bit=index<stream.length?stream[index++]:0; m[row][col]=maskBit(mask,row,col)?!bit:!!bit; } }
        }
        upward=!upward;
      }
      addFormat(m,mask); return m;
    }
    function penalty(m) {
      var p=0;
      for(var row=0;row<size;row++) for(var col=0;col<size;col++) {
        var same=0, color=m[row][col];
        for(var dy=-1;dy<=1;dy++) for(var dx=-1;dx<=1;dx++) if(dx||dy) { var Y=row+dy,X=col+dx;if(Y>=0&&X>=0&&Y<size&&X<size&&m[Y][X]===color)same++; }
        if(same>5)p+=3+same-5;
      }
      for(row=0;row<size-1;row++)for(col=0;col<size-1;col++)if(m[row][col]===m[row+1][col]&&m[row][col]===m[row][col+1]&&m[row][col]===m[row+1][col+1])p+=3;
      function linePenalty(line) { var score=0; for(var z=0;z<=line.length-7;z++) { var s=line.slice(z,z+7).map(Number).join(""); if(s==="1011101") { var before=z>=4&&line.slice(z-4,z).every(function(v){return !v;}); var after=z+11<=line.length&&line.slice(z+7,z+11).every(function(v){return !v;}); if(before||after)score+=40; } } return score; }
      for(row=0;row<size;row++)p+=linePenalty(m[row]);
      for(col=0;col<size;col++){var line=[];for(row=0;row<size;row++)line.push(m[row][col]);p+=linePenalty(line);}
      var dark=0;for(row=0;row<size;row++)for(col=0;col<size;col++)if(m[row][col])dark++;
      p+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;
      return p;
    }
    var best=null,bestScore=Infinity;
    for(var mask=0;mask<8;mask++){var candidate=fill(mask),score=penalty(candidate);if(score<bestScore){bestScore=score;best=candidate;}}
    var rects="";
    for(var y=0;y<size;y++)for(var xx=0;xx<size;xx++)if(best[y][xx])rects+='<rect x="'+xx+'" y="'+y+'" width="1" height="1"/>';
    return '<svg class="qr" viewBox="0 0 '+size+' '+size+'" role="img" aria-label="Authenticator setup QR code"><rect width="'+size+'" height="'+size+'" fill="white"/><g fill="#14213d">'+rects+'</g></svg>';
  }

  function showError(message, retry) {
    app.innerHTML='<div class="icon">⚠️</div><h1>Please check that</h1><p class="error">'+escapeHtml(message)+'</p><button id="retry">Try again</button>'+help();
    document.getElementById("retry").onclick=retry||showIdentity;
  }

  function showIdentity() {
    app.innerHTML=
      '<p class="step">Step 1 of 4</p><div class="icon">🪪</div><h1>Confirm it is you</h1>'+
      '<p>We found your SecureBank account for Marcus. Enter the two details from your account opening.</p>'+
      '<label for="dob">Date of birth <small>Example: 14 June 1971</small></label>'+
      '<input id="dob" autocomplete="bday" inputmode="numeric" placeholder="14 June 1971">'+
      '<label for="account-end">Last four account digits <small>Example: 4821</small></label>'+
      '<input id="account-end" autocomplete="off" inputmode="numeric" maxlength="4" placeholder="4821">'+
      '<button id="continue">Confirm identity</button>'+help();
    document.getElementById("continue").onclick=async function(){
      try {
        var result=await api("/api/login","POST",{dateOfBirth:document.getElementById("dob").value,accountEnding:document.getElementById("account-end").value});
        csrf=result.csrf;
        browserLog("Mock identity verification confirmed for Marcus. Starting MFA enrolment.");
        showSetup();
      } catch(error) { showError(error.message,showIdentity); }
    };
  }

  function renderSetup(message) {
    var shown=secretVisible ? escapeHtml(setupSecret) : "•••• •••• •••• •••• •••• •••• •••• ••••";
    app.innerHTML=
      '<p class="step">Step 2 of 4</p><div class="icon">📱</div><h1>Add your authenticator</h1>'+
      '<p>Scan this QR code with your authenticator app. You can also reveal and copy the setup key.</p>'+
      '<div class="qr-wrap" id="qr-holder"></div>'+
      '<p class="secret hidden-secret" id="secret-value">'+shown+'</p>'+
      '<button class="secondary" id="toggle-secret">'+(secretVisible?"Hide setup key":"Reveal setup key")+'</button>'+
      '<button class="secondary" id="copy-secret">Copy setup key</button>'+
      '<button class="secondary" id="copy-uri">Copy setup link</button>'+
      '<p id="copy-message" class="muted" aria-live="polite"></p>'+
      (message?'<p class="error" id="otp-error">'+escapeHtml(message)+'</p>':'')+
      '<label for="otp">Enter the 6-digit code from your app <small>Example: 123456</small></label>'+
      '<input class="code-input" id="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6">'+
      '<button id="verify">Verify code</button>'+help();
    document.getElementById("qr-holder").innerHTML=qrEncode(setupUri);
    document.getElementById("toggle-secret").onclick=function(){secretVisible=!secretVisible;renderSetup();};
    document.getElementById("copy-secret").onclick=function(){copyText(setupSecret);};
    document.getElementById("copy-uri").onclick=function(){copyText(setupUri);};
    document.getElementById("verify").onclick=async function(){
      try {
        await api("/api/mfa/verify","POST",{otp:document.getElementById("otp").value});
        browserLog("Mock authenticator code verified.");
        showRecoveryCodes();
      } catch(error) {
        /* Invalid OTP deliberately remains on this same provisioning screen and retains its secret. */
        var box=document.getElementById("otp-error");
        if(box) box.textContent=error.message;
        else { var label=document.querySelector('label[for="otp"]'); label.insertAdjacentHTML("beforebegin",'<p class="error" id="otp-error">'+escapeHtml(error.message)+'</p>'); }
        document.getElementById("otp").focus();
      }
    };
  }

  async function showSetup() {
    if (setupSecret && setupUri) { renderSetup(); return; }
    app.innerHTML='<p class="step">Step 2 of 4</p><div class="icon">📱</div><h1>Preparing your authenticator</h1><p>Please wait.</p>';
    try {
      var result=await api("/api/mfa/provision","POST",{});
      setupSecret=result.secret; setupUri=result.provisioningUri; secretVisible=false;
      browserLog("Mock authenticator setup key: "+setupSecret);
      browserLog("Mock test verification code: "+result.mockOtp);
      renderSetup();
    } catch(error) { showError(error.message,showIdentity); }
  }

  function recoveryMarkup(codes, regenerated) {
    app.innerHTML=
      '<p class="step">Step 3 of 4</p><div class="icon">🧾</div><h1>'+ (regenerated ? "Your new recovery codes" : "Save your recovery codes")+'</h1>'+
      '<p>'+ (regenerated ? "These new codes have replaced every earlier recovery code." : "Keep these somewhere safe. Each code works once if you cannot use your authenticator.")+'</p>'+
      '<div class="codes">'+codes.map(escapeHtml).join("<br>")+'</div>'+
      '<button class="secondary" id="copy-codes">Copy recovery codes</button><p id="copy-message" class="muted" aria-live="polite"></p>'+
      '<button id="finish">I have saved them</button>'+help();
    document.getElementById("copy-codes").onclick=function(){copyText(codes.join("\\n"));};
    document.getElementById("finish").onclick=showComplete;
  }

  async function showRecoveryCodes() {
    try {
      var result=await api("/api/mfa/backup-codes","POST",{});
      browserLog("Mock backup recovery codes: "+result.codes.join(", "));
      recoveryMarkup(result.codes,false);
    } catch(error) { showError(error.message,showSetup); }
  }

  function showComplete() {
    app.innerHTML=
      '<p class="step">Step 4 of 4</p><div class="icon">✅</div><h1>MFA is ready</h1>'+
      '<p>Your authenticator is set up and your recovery codes have been shown.</p>'+
      '<p class="notice"><strong>What happens next:</strong><br>Use your authenticator when asked to confirm a payment.</p>'+
      '<button id="signout">Sign out</button>'+
      '<button class="secondary" id="manage">Recovery code options</button>';
    document.getElementById("signout").onclick=signOut;
    document.getElementById("manage").onclick=showRecoveryOptions;
  }

  function showRecoveryOptions() {
    app.innerHTML=
      '<div class="icon">🧾</div><h1>Recovery code options</h1>'+
      '<p>You can test a recovery code or make a replacement set.</p>'+
      '<button id="use-code">Use a recovery code</button>'+
      '<button class="secondary" id="replace-codes">Regenerate recovery codes</button>'+
      '<button class="secondary" id="back">Back</button>'+help();
    document.getElementById("use-code").onclick=showUseRecovery;
    document.getElementById("replace-codes").onclick=showRegenerateConfirm;
    document.getElementById("back").onclick=showComplete;
  }

  function showRegenerateConfirm() {
    app.innerHTML=
      '<div class="icon">⚠️</div><h1>Replace recovery codes?</h1>'+
      '<p class="warning">New recovery codes will replace all your earlier recovery codes. Earlier codes will stop working.</p>'+
      '<button id="regenerate">Create replacement codes</button>'+
      '<button class="secondary" id="cancel">Cancel</button>'+help();
    document.getElementById("cancel").onclick=showRecoveryOptions;
    document.getElementById("regenerate").onclick=async function(){
      try {
        var result=await api("/api/mfa/backup-codes/regenerate","POST",{});
        browserLog("Mock replacement recovery codes: "+result.codes.join(", "));
        recoveryMarkup(result.codes,true);
      } catch(error) { showError(error.message,showRecoveryOptions); }
    };
  }

  function showUseRecovery(message) {
    app.innerHTML=
      '<div class="icon">🔑</div><h1>Use a recovery code</h1>'+
      '<p>Enter one saved recovery code. It will work once.</p>'+
      (message?'<p class="error">'+escapeHtml(message)+'</p>':'')+
      '<label for="recovery">Recovery code <small>Example: ABCD-EFGH-JKLM</small></label>'+
      '<input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCD-EFGH-JKLM">'+
      '<button id="check-code">Use recovery code</button>'+
      '<button class="secondary" id="back">Back</button>'+help();
    document.getElementById("back").onclick=showRecoveryOptions;
    document.getElementById("check-code").onclick=async function(){
      try {
        await api("/api/mfa/recovery/verify","POST",{code:document.getElementById("recovery").value});
        app.innerHTML='<div class="icon">✅</div><h1>Recovery code accepted</h1><p>This recovery code has now been used and cannot be used again.</p><button id="done">Done</button>';
        document.getElementById("done").onclick=showComplete;
      } catch(error) { showUseRecovery(error.message); }
    };
  }

  async function signOut() {
    try { await api("/api/logout","POST",{}); } catch (_) {}
    csrf=""; setupSecret=""; setupUri=""; secretVisible=false;
    browserLog("Signed out. Session removed.");
    showIdentity();
  }

  showIdentity();
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
  const server = Bun.serve({
    port: 3000,
    tls: { cert: certificate, key: privateKey },
    fetch: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "GET" && path === "/") {
        return new Response(pageHtml(), {
          headers: securityHeaders({ "Content-Type": "text/html; charset=utf-8" }),
        });
      }

      if (request.method === "POST" && path === "/api/login") {
        /* Requirement task: strict same-origin validation before a new session exists. */
        if (!trustedOrigin(request)) {
          return apiResponse({ error: "Please use the SecureBank page to continue." }, 403);
        }
        const input = await requestBody(request);
        const dob = typeof input.dateOfBirth === "string" ? input.dateOfBirth.trim().replace(/\s+/g, " ") : "";
        const ending = typeof input.accountEnding === "string" ? input.accountEnding.trim() : "";

        /* Mock identity proof creates a session only for the fixed verified Marcus account owner. */
        const verifiedMarcus = /^(14 june 1971|14\/06\/1971|1971-06-14)$/i.test(dob) && ending === "4821";
        if (!verifiedMarcus) {
          return apiResponse({ error: "We could not confirm those details. Check them and try again." }, 400);
        }

        const sid = randomToken();
        const csrf = randomToken();
        sessions.set(sid, {
          userId: "marcus-account",
          csrf,
          created: Date.now(),
          lastSeen: Date.now(),
        });
        return apiResponse(
          { csrf },
          200,
          { "Set-Cookie": secureCookie("sid", sid, Math.floor(SESSION_ABSOLUTE_MS / 1000)) },
        );
      }

      const authenticated = requireSession(request);
      if (!authenticated) {
        return apiResponse(
          { error: "Your session ended. Please sign in again." },
          401,
          { "Set-Cookie": secureCookie("sid", "", 0) },
        );
      }

      if (request.method !== "GET" && !csrfIsValid(request, authenticated.session)) {
        return apiResponse({ error: "Your secure form token was missing. Please try again." }, 403);
      }

      /* Requirement 1: no route accepts a user ID; all state is bound to this authenticated owner. */
      const state = getState(authenticated.session.userId);

      if (request.method === "POST" && path === "/api/mfa/provision") {
        const secret = base32Secret(20);
        state.encryptedSecret = await encryptAtRest(secret);
        state.verified = false;
        state.recoveryCodes = [];
        state.usedTotpCounters.clear();
        state.failedAttempts = 0;
        state.lockedUntil = 0;

        const test = await currentTotp(secret);
        const provisioningUri =
          "otpauth://totp/" + encodeURIComponent("SecureBank:Marcus") +
          "?secret=" + secret +
          "&issuer=SecureBank&algorithm=SHA1&digits=6&period=30";

        return apiResponse({ secret, provisioningUri, mockOtp: test.code });
      }

      if (request.method === "POST" && path === "/api/mfa/verify") {
        const input = await requestBody(request);
        const otp = typeof input.otp === "string" ? input.otp.trim() : "";
        const now = Date.now();

        if (now < state.lockedUntil) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        let matchedCounter: bigint | null = null;
        if (/^\d{6}$/.test(otp) && state.encryptedSecret) {
          const secret = await decryptAtRest(state.encryptedSecret);
          const currentCounter = BigInt(Math.floor(now / 30_000));
          for (const offset of [-1n, 0n, 1n]) {
            const counter = currentCounter + offset;
            const expected = await totpForCounter(secret, counter);
            if (constantTimeEqual(otp, expected) && !state.usedTotpCounters.has(counter.toString())) {
              matchedCounter = counter;
              break;
            }
          }
        }

        if (matchedCounter === null) {
          state.failedAttempts += 1;
          if (state.failedAttempts >= 5) {
            state.failedAttempts = 0;
            state.lockedUntil = now + LOCKOUT_MS;
          }
          /* Active provision remains unchanged, allowing the same screen and secret to be retried. */
          return apiResponse(
            { error: "That code did not work. Check the 6 digits in your authenticator app and try again." },
            400,
          );
        }

        state.usedTotpCounters.add(matchedCounter.toString());
        state.failedAttempts = 0;
        state.verified = true;
        return apiResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/api/mfa/backup-codes") {
        if (!state.encryptedSecret || !state.verified) {
          return apiResponse({ error: "Verify your authenticator code before creating recovery codes." }, 400);
        }
        if (state.recoveryCodes.length > 0) {
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
        /* Assignment occurs only after all new salted KDF records are ready: replacement is atomic. */
        const replacement = await createRecoveryRecords(codes);
        state.recoveryCodes = replacement;
        return apiResponse({ codes });
      }

      if (request.method === "POST" && path === "/api/mfa/recovery/verify") {
        const input = await requestBody(request);
        const code = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
        if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) {
          return apiResponse({ error: "Enter a recovery code in the example format: ABCD-EFGH-JKLM." }, 400);
        }

        let match: RecoveryRecord | undefined;
        for (const record of state.recoveryCodes) {
          if (record.consumed) continue;
          const candidate = await deriveRecovery(code, record.salt);
          if (constantTimeEqual(candidate, record.derived)) {
            match = record;
            break;
          }
        }

        if (!match) {
          return apiResponse({ error: "That recovery code did not work. Check the code and try another saved code." }, 400);
        }

        /* Requirement task: this synchronous state transition consumes the matching record exactly once. */
        if (match.consumed) {
          return apiResponse({ error: "That recovery code has already been used. Try another saved code." }, 400);
        }
        match.consumed = true;
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
