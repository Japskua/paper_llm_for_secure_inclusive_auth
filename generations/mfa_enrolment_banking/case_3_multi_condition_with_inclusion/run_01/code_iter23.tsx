
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem

 Requirement sections:
 - Security 1: session ownership, CSRF, no IDOR
 - Security 2: HTTPS headers, secure cookie, generic failures
 - Security 3: encrypted authenticator seeds and work-factored recovery records
 - Security 4: strict JSON/input validation and safe client rendering
 - Security 5: challenge expiry, single use, rate limiting, session expiry
*/
const encoder = new TextEncoder();
const sessions = new Map<string, any>();
const preAuthTokens = new Map<string, number>();
const signInFailures = new Map<string, { count: number; lockedUntil: number }>();

const account = {
  id: "marcus-account-001",
  email: "marcus@example.com",
  password: "BankDemo!42",
  enabled: false,
  encryptedSeed: null as any,
  recoveryRecords: [] as Array<{ salt: string; hash: string }>
};

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 10 * 60 * 1000;
const LOCK_MS = 60 * 1000;
const MAX_FAILURES = 5;
const RECOVERY_KDF_ITERATIONS = 120000;
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

function random(bytes = 24) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function secureInt(max: number) {
  const limit = Math.floor(0x100000000 / max) * max;
  const a = new Uint32Array(1);
  do crypto.getRandomValues(a); while (a[0] >= limit);
  return a[0] % max;
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let output = "";
  for (let i = 0; i < 10; i++) {
    if (i === 5) output += "-";
    output += alphabet[secureInt(alphabet.length)];
  }
  return output;
}
/* Security 3: RFC 4648 Base32, with only A-Z and 2-7 characters. */
function base32(bytes: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = "";
  for (const byte of bytes) {
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
function provisioningSecret() {
  return base32(crypto.getRandomValues(new Uint8Array(20)));
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.replace(/\s|=/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("Invalid Base32");
  let bits = 0, accumulator = 0;
  const out: number[] = [];
  for (const character of clean) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      out.push((accumulator >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
/* Security 3/5: standard RFC 6238 TOTP using HMAC-SHA-1 and 30 second steps. */
async function totp(seed: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey(
    "raw", base32Bytes(seed), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const message = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(value & 255n);
    value >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[19] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}
function sameText(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(ciphertext).toString("base64url") };
}
async function decrypt(record: { iv: string; data: string }) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(record.iv, "base64url") },
    encryptionKey,
    Buffer.from(record.data, "base64url")
  );
  return new TextDecoder().decode(plain);
}
/* Security 3: every recovery code receives an independent PBKDF2 salt and hash. */
async function recoveryRecord(code: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: RECOVERY_KDF_ITERATIONS },
    key, 256
  );
  return { salt: Buffer.from(salt).toString("base64url"), hash: Buffer.from(bits).toString("base64url") };
}
async function recoveryMatches(code: string, record: { salt: string; hash: string }) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(record.salt, "base64url"), iterations: RECOVERY_KDF_ITERATIONS },
    key, 256
  );
  return sameText(Buffer.from(bits).toString("base64url"), record.hash);
}
function cookies(r: Request) {
  const output: Record<string, string> = {};
  for (const piece of (r.headers.get("cookie") || "").split(";")) {
    const at = piece.indexOf("=");
    if (at > 0) output[piece.slice(0, at).trim()] = piece.slice(at + 1).trim();
  }
  return output;
}
function trusted(r: Request) {
  const url = new URL(r.url);
  return url.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
}
function secureHeaders(r: Request, nonce = "") {
  const origin = new URL(r.url).origin;
  return new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, private",
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin"
  });
}
function respond(r: Request, payload: any, status = 200, extra: Record<string, string> = {}) {
  const h = secureHeaders(r);
  h.set("Content-Type", "application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra)) h.set(key, value);
  return new Response(JSON.stringify(payload), { status, headers: h });
}
function sessionId(r: Request) {
  return cookies(r).mfa_session || "";
}
function authorized(r: Request) {
  const id = sessionId(r);
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.createdAt > SESSION_ABSOLUTE_MS || now - session.lastSeen > SESSION_IDLE_MS) {
    sessions.delete(id);
    return null;
  }
  if (session.userId !== account.id) return null;
  session.lastSeen = now;
  return session;
}
function csrfOK(r: Request, session: any) {
  const url = new URL(r.url);
  return r.headers.get("origin") === url.origin &&
    typeof r.headers.get("x-csrf-token") === "string" &&
    r.headers.get("x-csrf-token") === session.csrf;
}
async function readJSON(r: Request, allowed: string[]) {
  if (!String(r.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) return null;
  try {
    const value = await r.json();
    if (!value || Array.isArray(value) || typeof value !== "object") return null;
    if (Object.keys(value).some(k => !allowed.includes(k))) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}
function retryMessage(ms: number) {
  return `Please wait ${Math.max(1, Math.ceil(ms / 1000))} seconds before trying again.`;
}
function failureEntry(map: Map<string, { count: number; lockedUntil: number }>, key: string) {
  const entry = map.get(key) || { count: 0, lockedUntil: 0 };
  map.set(key, entry);
  return entry;
}
function provisioningURI(seed: string) {
  return "otpauth://totp/" + encodeURIComponent("Northstar Bank:" + account.email) +
    "?secret=" + seed + "&issuer=" + encodeURIComponent("Northstar Bank") +
    "&algorithm=SHA1&digits=6&period=30";
}
async function setupPayload(session: any) {
  if (!session.provision) return null;
  const seed = await decrypt(session.provision.seed);
  return {
    ok: true,
    secret: seed,
    uri: provisioningURI(seed),
    message: "Your authenticator setup is ready.",
    ...(session.demo ? { mockOtp: session.provision.testOtp } : {})
  };
}
function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

async function handle(r: Request): Promise<Response> {
  const url = new URL(r.url);
  if (!trusted(r)) return new Response("Not found", { status: 404, headers: secureHeaders(r) });

  if (r.method === "GET" && url.pathname === "/") {
    const nonce = random(18);
    const h = secureHeaders(r, nonce);
    h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers: h });
  }
  if (r.method === "GET" && url.pathname === "/api/preauth") {
    const token = random(24);
    preAuthTokens.set(token, Date.now() + 10 * 60 * 1000);
    return respond(r, { ok: true, csrf: token });
  }
  if (r.method === "POST" && url.pathname === "/api/signin") {
    const d = await readJSON(r, ["email", "password", "csrf", "demo"]);
    if (!d || typeof d.email !== "string" || typeof d.password !== "string" ||
      typeof d.csrf !== "string" || typeof d.demo !== "boolean" ||
      d.email.length > 254 || d.password.length > 128 || d.csrf.length < 20 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)) {
      return respond(r, { ok: false, message: "Enter a valid email address and password, then try again." }, 400);
    }
    const expiry = preAuthTokens.get(d.csrf);
    preAuthTokens.delete(d.csrf);
    if (!expiry || expiry < Date.now() || r.headers.get("origin") !== url.origin) {
      return respond(r, { ok: false, message: "Please refresh the page and try signing in again." }, 403);
    }
    const key = d.email.trim().toLowerCase();
    const limit = failureEntry(signInFailures, key);
    if (limit.lockedUntil > Date.now()) return respond(r, { ok: false, message: retryMessage(limit.lockedUntil - Date.now()) }, 429);
    if (key !== account.email || d.password !== account.password) {
      limit.count++;
      if (limit.count >= MAX_FAILURES) {
        limit.count = 0;
        limit.lockedUntil = Date.now() + LOCK_MS;
      }
      return respond(r, {
        ok: false,
        message: limit.lockedUntil > Date.now() ? retryMessage(limit.lockedUntil - Date.now()) : "Sign-in could not be completed. Check your email and password, then try again."
      }, limit.lockedUntil > Date.now() ? 429 : 401);
    }
    signInFailures.delete(key);
    const id = random(32), csrf = random(24), now = Date.now();
    sessions.set(id, { userId: account.id, csrf, createdAt: now, lastSeen: now, demo: d.demo, provision: null });
    return respond(r, { ok: true, csrf }, 200, {
      "Set-Cookie": `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`
    });
  }

  const session = authorized(r);
  if (!session) return respond(r, { ok: false, message: "Please sign in again to continue." }, 401, { "Set-Cookie": clearCookie() });

  if (r.method === "GET" && url.pathname === "/api/session-status") {
    const step = account.enabled ? "complete" : session.provision ? "setup" : "start";
    return respond(r, { ok: true, csrf: session.csrf, email: account.email, enabled: account.enabled, step, demo: session.demo });
  }
  if (r.method === "GET" && url.pathname === "/api/setup-view") {
    if (!session.provision || account.enabled) return respond(r, { ok: false, message: "Start authenticator setup first." }, 400);
    return respond(r, await setupPayload(session));
  }
  if (r.method !== "POST" || !csrfOK(r, session)) {
    return respond(r, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  }
  if (url.pathname === "/api/logout") {
    sessions.delete(sessionId(r));
    return respond(r, { ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (url.pathname === "/api/provision") {
    const d = await readJSON(r, []);
    if (!d) return respond(r, { ok: false, message: "Please try setup again." }, 400);
    const now = Date.now();
    const seed = provisioningSecret();
    session.provision = {
      seed: await encrypt(seed),
      issuedAt: now,
      expiresAt: now + CHALLENGE_MS,
      used: false,
      failedAttempts: 0,
      lockedUntil: 0,
      acceptedCounters: new Set<number>(),
      /* Deterministic test-only path. It is intentionally returned only to a demo browser UI. */
      testOtp: "654321"
    };
    return respond(r, await setupPayload(session));
  }
  if (url.pathname === "/api/verify-otp") {
    const d = await readJSON(r, ["otp"]);
    if (!d || typeof d.otp !== "string" || !/^\d{6}$/.test(d.otp)) {
      return respond(r, { ok: false, message: "Enter exactly six numbers. For example: 123456." }, 400);
    }
    const challenge = session.provision;
    if (!challenge || account.enabled) return respond(r, { ok: false, message: "Start authenticator setup again, then enter its six-number code." }, 400);
    const now = Date.now();
    if (challenge.used || challenge.expiresAt <= now) {
      session.provision = null;
      return respond(r, { ok: false, message: "That setup has expired or was already used. Choose Restart setup for a new code." }, 400);
    }
    if (challenge.lockedUntil > now) return respond(r, { ok: false, message: retryMessage(challenge.lockedUntil - now) }, 429);

    const seed = await decrypt(challenge.seed);
    const currentCounter = Math.floor(now / 30000);
    let matchedCounter: number | null = null;
    for (const counter of [currentCounter - 1, currentCounter, currentCounter + 1]) {
      if (!challenge.acceptedCounters.has(counter) && sameText(d.otp, await totp(seed, counter))) {
        matchedCounter = counter;
        break;
      }
    }
    const validDemoCode = session.demo && sameText(d.otp, challenge.testOtp);
    if (matchedCounter === null && !validDemoCode) {
      challenge.failedAttempts++;
      if (challenge.failedAttempts >= MAX_FAILURES) {
        challenge.failedAttempts = 0;
        challenge.lockedUntil = now + LOCK_MS;
        return respond(r, { ok: false, message: retryMessage(LOCK_MS) }, 429);
      }
      return respond(r, { ok: false, message: "Those six numbers do not match. Check your authenticator app and enter its current six-number code." }, 400);
    }
    if (matchedCounter !== null) challenge.acceptedCounters.add(matchedCounter);
    challenge.used = true;
    const codes = Array.from({ length: 10 }, recoveryCode);
    account.encryptedSeed = challenge.seed;
    account.recoveryRecords = await Promise.all(codes.map(recoveryRecord));
    account.enabled = true;
    session.provision = null;
    return respond(r, { ok: true, codes, message: "Your authenticator is connected." });
  }
  if (url.pathname === "/api/recovery/regenerate") {
    const d = await readJSON(r, []);
    if (!d || !account.enabled) return respond(r, { ok: false, message: "Your authenticator needs to be connected first." }, 400);
    const codes = Array.from({ length: 10 }, recoveryCode);
    account.recoveryRecords = await Promise.all(codes.map(recoveryRecord));
    return respond(r, { ok: true, codes, message: "Your old recovery codes no longer work. Save these new codes now." });
  }
  if (url.pathname === "/api/recovery/verify") {
    const d = await readJSON(r, ["code"]);
    if (!d || typeof d.code !== "string" || !/^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(d.code.toUpperCase())) {
      return respond(r, { ok: false, message: "Enter one recovery code in the format ABCDE-23456." }, 400);
    }
    const code = d.code.toUpperCase();
    let found = -1;
    for (let i = 0; i < account.recoveryRecords.length; i++) {
      if (await recoveryMatches(code, account.recoveryRecords[i])) { found = i; break; }
    }
    if (found < 0) return respond(r, { ok: false, message: "That recovery code cannot be used. Check the code and try again." }, 400);
    account.recoveryRecords.splice(found, 1);
    return respond(r, { ok: true, message: "Recovery code accepted. It cannot be used again." });
  }
  return new Response("Not found", { status: 404, headers: secureHeaders(r) });
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:#162435;font:17px/1.72 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:610px;margin:auto;padding:18px 16px 38px}header{padding:8px 4px 17px}h1{font-size:1.45rem;margin:0}h2{font-size:1.3rem;line-height:1.35;margin:0 0 12px}h3{font-size:1rem;margin:19px 0 7px}.step{font-size:.92rem;color:#35516e;margin:4px 0}.card,.logs{background:#fff;border:1px solid #c7d5e3;border-radius:16px;padding:22px;box-shadow:0 2px 10px #17395c0d}.logs{margin-top:16px}.notice,.hint,.success{padding:12px 13px;border-radius:10px;margin:12px 0}.notice{background:#fff2df;border-left:5px solid #bd6b00}.hint{background:#eef6ff;border-left:5px solid #2167b5}.success{background:#e9f8ef;border-left:5px solid #16744a}label{font-weight:bold;display:block;margin-top:14px}input,button{width:100%;min-height:52px;margin:7px 0;border-radius:10px;font:inherit;letter-spacing:inherit}input{border:2px solid #9caebe;padding:10px;background:#fff}button{cursor:pointer;border:0;background:#125ab5;color:#fff;font-weight:bold;padding:10px}button:hover{filter:brightness(.96)}button:focus,input:focus{outline:4px solid #f0bc43;outline-offset:2px}.secondary{background:#fff;color:#125ab5;border:2px solid #125ab5;font-weight:normal}.quiet{font-size:.92rem}.secret{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;overflow-wrap:anywhere;background:#f2f6fa;padding:12px;border-radius:9px;border:1px solid #d4e0ea}.qr{width:min(360px,100%);height:auto;display:block;margin:16px auto;border:8px solid white;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes .secret{font-size:.84rem;padding:9px}.row{display:flex;gap:9px}.row button{width:auto;flex:1}.hidden{display:none}.divider{border:0;border-top:1px solid #dbe3ec;margin:22px 0}.demo{display:flex;gap:10px;align-items:center;background:#fff8dc;padding:10px;border-radius:9px;font-size:.9rem}.demo input{width:22px;min-height:22px;margin:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.55 ui-monospace,monospace;margin:0}@media(max-width:390px){body{font-size:16px}.card,.logs{padding:17px}.codes{grid-template-columns:1fr}}
</style></head><body><main>
<header><h1>✦ Northstar Bank</h1><p class="step">Security setup · Take your time. There is no reading timer.</p></header>
<section id="app" class="card" aria-live="polite"></section>
<aside class="logs" aria-label="Browser simulation logs"><h2>Logs</h2><p class="quiet">Simulation messages shown in the browser console also appear here.</p><pre id="logs">Ready.</pre></aside>
</main><script nonce="${nonce}">
"use strict";
let csrf="",setupSecret="",setupURI="",demoMode=false;
const app=document.querySelector("#app"),logs=document.querySelector("#logs");
function esc(v){const e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function browserLog(label,value){const line=value===undefined?label:label+" "+(Array.isArray(value)?value.join(", "):String(value));console.log(label,value===undefined?"":value);logs.textContent+=(logs.textContent?"\\n":"")+line}
async function get(path){const r=await fetch(path,{credentials:"same-origin"});let d={};try{d=await r.json()}catch{}return {r,d}}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let d={};try{d=await r.json()}catch{}return {r,d}}
function message(text,kind="notice"){return text?'<p class="'+kind+'">'+esc(text)+"</p>":""}
function copyText(text,b){if(navigator.clipboard)navigator.clipboard.writeText(text).then(()=>{b.textContent="Copied";setTimeout(()=>b.textContent="Copy",1400)}).catch(()=>fallbackCopy(text,b));else fallbackCopy(text,b)}
function fallbackCopy(text,b){const a=document.createElement("textarea");a.value=text;a.style.cssText="position:fixed;opacity:0";document.body.append(a);a.select();try{document.execCommand("copy");b.textContent="Copied"}catch{b.textContent="Select the text above"}a.remove();setTimeout(()=>b.textContent="Copy",1600)}
async function boot(){const x=await get("/api/session-status");if(!x.r.ok)return signin();csrf=x.d.csrf;demoMode=!!x.d.demo;if(x.d.step==="setup")return loadSetup();if(x.d.step==="complete")return complete();start()}
async function signin(note=""){const pre=await get("/api/preauth"),token=pre.d.csrf||"";app.innerHTML='<h2>Confirm your account</h2>'+message(note)+'<p class="hint">Help: use the email and password for your bank account. Example email: name@example.com.</p><label for="email">Email address</label><input id="email" autocomplete="email" inputmode="email" placeholder="name@example.com" maxlength="254"><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" maxlength="128"><label class="demo"><input id="demo" type="checkbox"> <span><strong>Demo/testing mode</strong><br>Show the safe test code and recovery codes in this browser only.</span></label><button id="continue">Continue</button>';document.querySelector("#continue").onclick=async()=>{const d={email:document.querySelector("#email").value,password:document.querySelector("#password").value,csrf:token,demo:document.querySelector("#demo").checked};const r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}),x=await r.json();if(!r.ok)return signin(x.message);csrf=x.csrf;demoMode=d.demo;browserLog("Sign-in simulation completed.");start()}}
function start(note=""){app.innerHTML='<p class="step">Step 1 of 3</p><h2>Add your authenticator app</h2>'+message(note)+'<p>Use an authenticator app on your phone. You can scan a setup image or copy a setup secret.</p><p class="hint">Help: this creates a new setup. You can restart safely if needed.</p><button id="show">Show secure setup</button>';document.querySelector("#show").onclick=provision}
async function provision(){const x=await api("/api/provision");if(!x.r.ok)return start(x.d.message);setupSecret=x.d.secret;setupURI=x.d.uri;if(x.d.mockOtp)browserLog("Demo test OTP:",x.d.mockOtp);browserLog("Authenticator provisioning simulation completed.");showSetup()}
async function loadSetup(){const x=await get("/api/setup-view");if(!x.r.ok)return start(x.d.message);setupSecret=x.d.secret;setupURI=x.d.uri;if(x.d.mockOtp)browserLog("Demo test OTP:",x.d.mockOtp);showSetup()}
function showSetup(){app.innerHTML='<p class="step">Step 2 of 3</p><h2>Your setup is ready</h2><p class="hint">Help: scan this image in your authenticator app. If scanning is difficult, reveal and copy the secret instead.</p><canvas id="qr" class="qr" aria-label="Scannable authenticator setup QR code"></canvas><div class="row"><button id="reveal" class="secondary">Reveal secret</button><button id="copyuri" class="secondary">Copy setup link</button></div><div id="secretarea" class="hidden"><p class="secret" id="secret"></p><button id="copysecret" class="secondary">Copy</button></div><button id="next">I added it to my app</button><button id="restart" class="secondary">Restart setup</button>';renderQR(document.querySelector("#qr"),setupURI);document.querySelector("#reveal").onclick=()=>{const a=document.querySelector("#secretarea");a.classList.toggle("hidden");document.querySelector("#reveal").textContent=a.classList.contains("hidden")?"Reveal secret":"Hide secret";document.querySelector("#secret").textContent=setupSecret};document.querySelector("#copysecret").onclick=e=>copyText(setupSecret,e.currentTarget);document.querySelector("#copyuri").onclick=e=>copyText(setupURI,e.currentTarget);document.querySelector("#restart").onclick=provision;document.querySelector("#next").onclick=verify}
function verify(note=""){app.innerHTML='<p class="step">Step 3 of 3</p><h2>Check your app</h2>'+message(note)+'<p>Enter the six numbers shown in your authenticator app.</p><p class="hint">Help: there is plenty of time. Example: 123456. You can return to setup or restart without penalty.</p><label for="otp">Six-number code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button id="verify">Verify code</button><button id="back" class="secondary">Return to setup</button>';document.querySelector("#back").onclick=showSetup;document.querySelector("#verify").onclick=async()=>{const x=await api("/api/verify-otp",{otp:document.querySelector("#otp").value.trim()});if(!x.r.ok)return verify(x.d.message);browserLog("Authenticator verification simulation succeeded.");if(demoMode)browserLog("Returned recovery codes:",x.d.codes);saveCodes(x.d.codes,x.d.message)}}
function saveCodes(codes,note){const all=codes.join("\\n");app.innerHTML='<p class="step">Save recovery codes</p><h2>Save your recovery codes</h2>'+message(note,"success")+'<p>Use one code only if you cannot use your authenticator app. Keep them somewhere private.</p><p class="hint">Help: use Copy all, Download, or Print. You do not need to type these codes.</p><div class="codes">'+codes.map(c=>'<div class="secret">'+esc(c)+'</div>').join("")+'</div><button id="saved">I saved my codes</button><div class="row"><button id="copyall" class="secondary">Copy all</button><button id="download" class="secondary">Download</button><button id="print" class="secondary">Print</button></div><p id="saveconfirm" class="quiet"></p>';document.querySelector("#copyall").onclick=e=>{copyText(all,e.currentTarget);document.querySelector("#saveconfirm").textContent="Recovery codes copied. Save them in a private place."};document.querySelector("#download").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([all+"\\n"],{type:"text/plain"}));a.download="northstar-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)};document.querySelector("#print").onclick=()=>window.print();document.querySelector("#saved").onclick=complete}
function complete(note=""){app.innerHTML='<h2>Security setup complete</h2>'+message(note||"Your authenticator is active.","success")+'<p class="hint">Help: you are signed in securely. Recovery codes are only shown when they are created.</p><button id="signout">Sign out</button><hr class="divider"><h3>Recovery codes</h3><p class="quiet">If you need a fresh set, your old recovery codes will stop working.</p><button id="newcodes" class="secondary">Create new recovery codes</button><label for="recovery">Test one recovery code</label><input id="recovery" autocomplete="one-time-code" maxlength="11" placeholder="ABCDE-23456"><button id="useRecovery" class="secondary">Use recovery code</button><p id="recoveryResult" class="quiet"></p>';document.querySelector("#signout").onclick=logout;document.querySelector("#newcodes").onclick=async()=>{const x=await api("/api/recovery/regenerate");if(!x.r.ok)return complete(x.d.message);if(demoMode)browserLog("Returned recovery codes:",x.d.codes);saveCodes(x.d.codes,x.d.message)};document.querySelector("#useRecovery").onclick=async()=>{const x=await api("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim()});document.querySelector("#recoveryResult").textContent=x.d.message||"Please try again.";if(x.r.ok)browserLog("Recovery-code verification simulation succeeded.")}}
async function logout(){await api("/api/logout");csrf="";setupSecret="";setupURI="";browserLog("Sign-out simulation completed.");signin("You have signed out safely.")}

/* Standards-compliant QR encoder: QR Model 2, Version 10-L, byte mode, Reed-Solomon ECC. */
function renderQR(canvas,text){
 const version=10,n=57,dataCap=274,eccLen=18,blockSizes=[68,68,69,69],bytes=[...new TextEncoder().encode(text)];
 if(bytes.length>dataCap-3)throw new Error("Setup link is too long");
 const bits=[];const push=(v,count)=>{for(let i=count-1;i>=0;i--)bits.push((v>>>i)&1)};
 push(4,4);push(bytes.length,8);bytes.forEach(b=>push(b,8));push(0,Math.min(4,dataCap*8-bits.length));while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)};for(let i=data.length,p=0;i<dataCap;i++,p++)data.push(p%2?0x11:0xec);
 const mul=(a,b)=>{let z=0;while(b){if(b&1)z^=a;a=(a<<1)^((a&128)?0x11d:0);b>>>=1}return z};
 const pow=(a,k)=>{let x=1;while(k--)x=mul(x,a);return x};
 let divisor=[1];for(let i=0;i<eccLen;i++){const next=Array(divisor.length+1).fill(0);for(let j=0;j<divisor.length;j++){next[j]^=divisor[j];next[j+1]^=mul(divisor[j],pow(2,i))}divisor=next}
 const parity=block=>{const rem=Array(eccLen).fill(0);for(const value of block){const factor=value^rem.shift();rem.push(0);for(let j=0;j<eccLen;j++)rem[j]^=mul(divisor[j+1],factor)}return rem};
 let offset=0;const blocks=blockSizes.map(s=>data.slice(offset,offset+=s)),ecc=blocks.map(parity),stream=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.length)stream.push(b[i])});for(let i=0;i<eccLen;i++)ecc.forEach(e=>stream.push(e[i]));
 const matrix=Array.from({length:n},()=>Array(n).fill(null));
 const set=(x,y,v=true)=>{if(x>=0&&y>=0&&x<n&&y<n)matrix[y][x]=v};
 const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const edge=dx>=0&&dx<=6&&dy>=0&&dy<=6;set(x+dx,y+dy,edge&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))}};
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(let i=8;i<n-8;i++){if(matrix[6][i]===null)set(i,6,i%2===0);if(matrix[i][6]===null)set(6,i,i%2===0)}
 const align=(x,y)=>{for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)};
 [6,28,50].forEach(y=>[6,28,50].forEach(x=>{if(matrix[y][x]===null)align(x,y)}));set(8,n-8,true);
 for(let i=0;i<9;i++){if(matrix[8][i]===null)set(i,8,false);if(matrix[i][8]===null)set(8,i,false)}for(let i=0;i<8;i++){set(n-1-i,8,false);set(8,n-1-i,false)}
 let vb=version<<12;let q=vb;while(q>=0x1000){const sh=Math.floor(Math.log2(q))-12;q^=0x1f25<<sh}vb|=q;for(let i=0;i<18;i++){const b=((vb>>>i)&1)!==0;set(Math.floor(i/3),n-11+i%3,b);set(n-11+i%3,Math.floor(i/3),b)}
 const raw=[];stream.forEach(b=>{for(let i=7;i>=0;i--)raw.push((b>>>i)&1)});
 let k=0,up=true;for(let right=n-1;right>0;right-=2){if(right===6)right--;for(let z=0;z<n;z++){const y=up?n-1-z:z;for(let x=right;x>=right-1;x--)if(matrix[y][x]===null){let b=k<raw.length?raw[k++]:0;if((x+y)%2===0)b^=1;set(x,y,!!b)}}up=!up}
 const mask=0,format=(1<<3|mask);let fb=format<<10;q=fb;while(q>=0x400){const sh=Math.floor(Math.log2(q))-10;q^=0x537<<sh}fb=(fb|q)^0x5412;
 for(let i=0;i<15;i++){const b=((fb>>>i)&1)!==0;if(i<6)set(i,8,b);else if(i<8)set(i+1,8,b);else set(n-15+i,8,b);if(i<8)set(8,n-i-1,b);else if(i<9)set(8,15-i,b);else set(8,15-i-1,b)}
 const quiet=4,cell=6,total=(n+quiet*2)*cell,ctx=canvas.getContext("2d");canvas.width=canvas.height=total;ctx.fillStyle="#fff";ctx.fillRect(0,0,total,total);ctx.fillStyle="#000";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(matrix[y][x])ctx.fillRect((x+quiet)*cell,(y+quiet)*cell,cell,cell)
}
boot();
</script></body></html>`;
}

Bun.serve({
  hostname: "localhost",
  port: Number(Bun.env.PORT || 3000),
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: secureHeaders(request) });
    }
  }
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
