
/*
  Password Recovery System
  Security 1: Per-session CSRF tokens, Secure/HttpOnly cookies, protected actions.
  Security 3: TLS, HSTS, CSP, secure response headers, random expiring reset tokens.
  Security 4: Argon2id password hashing, password policy, throttling, MFA mock.
*/

type Session = {
  csrf: string;
  loginFailures: number;
  loginBlockedUntil: number;
  resetFailures: number;
  resetBlockedUntil: number;
  mfaFailures: number;
  mfaBlockedUntil: number;
  authenticated: boolean;
  recoveryStep: "start" | "verify" | "newPassword" | "signIn" | "mfa" | "complete";
  resetRequested: boolean;
  mfaCode?: string;
  mfaExpiresAt?: number;
  verifiedResetToken?: string;
};

type ResetRecord = {
  accountId: string;
  expiresAt: number;
  used: boolean;
  failures: number;
  blockedUntil: number;
};

type Account = {
  id: string;
  normalizedEmail: string;
  passwordHash: string;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();

/* Minimal recognized mock account record. No account identifiers are returned to clients. */
const helenaAccount: Account = {
  id: "account-helena-demo",
  normalizedEmail: "helena@example.test",
  passwordHash: await Bun.password.hash("HelenaStrong!2025", {
    algorithm: "argon2id",
  }),
};
const accountsByEmail = new Map<string, Account>([
  [helenaAccount.normalizedEmail, helenaAccount],
]);
const accountsById = new Map<string, Account>([[helenaAccount.id, helenaAccount]]);

function randomHex(bytes = 32): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let i = 0; i < left.length; i++) {
    different |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return different === 0;
}

function parseCookies(header: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) {
      cookies[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
    }
  }
  return cookies;
}

function getSession(request: Request): { sid: string; session: Session } {
  const sid = parseCookies(request.headers.get("cookie") || "").sid;
  if (sid && sessions.has(sid)) return { sid, session: sessions.get(sid)! };

  const newSid = randomHex();
  const session: Session = {
    csrf: randomHex(),
    loginFailures: 0,
    loginBlockedUntil: 0,
    resetFailures: 0,
    resetBlockedUntil: 0,
    mfaFailures: 0,
    mfaBlockedUntil: 0,
    authenticated: false,
    recoveryStep: "start",
    resetRequested: false,
  };
  sessions.set(newSid, session);
  return { sid: newSid, session };
}

function securityHeaders(sid: string, nonce: string): HeadersInit {
  return {
    "set-cookie": `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cache-control": "no-store",
    "content-security-policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      `connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
  };
}

function responseJson(data: unknown, sid: string, status = 200): Response {
  const nonce = randomHex(16);
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...securityHeaders(sid, nonce),
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function text(value: unknown, maxLength = 200): string {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

/* Password values are deliberately raw: never trim, slice, or normalize passwords. */
function rawString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function normalizeEmail(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function validCsrf(body: unknown, session: Session): boolean {
  if (!body || typeof body !== "object") return false;
  const csrf = (body as Record<string, unknown>).csrf;
  return typeof csrf === "string" && safeEqual(csrf, session.csrf);
}

function passwordIsStrong(password: string): boolean {
  return (
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^\w\s]/.test(password)
  );
}

function cleanExpiredTokens(): void {
  const now = Date.now();
  for (const [token, record] of resetTokens) {
    if (record.expiresAt < now || record.used) resetTokens.delete(token);
  }
}

function blockedMessage(until: number): string {
  const seconds = Math.max(1, Math.ceil((until - Date.now()) / 1000));
  return `Please pause and try again in about ${seconds} seconds.`;
}

function htmlPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f3f7f8;color:#14252e;font:18px/1.5 Arial,sans-serif}.wrap{width:min(100% - 32px,700px);margin:30px auto}header,main{background:#fff;padding:25px;margin-bottom:16px;border-radius:12px;box-shadow:0 1px 5px #0002}h1,h2{line-height:1.2}h1{margin:0 0 12px;font-size:1.65rem}h2{margin-top:0}.progress{display:flex;flex-wrap:wrap;gap:8px;padding:0;margin:16px 0 0;list-style:none}.progress li{padding:5px 10px;background:#e4ecee;border-radius:18px;font-size:.92rem}.progress li.active{background:#075d72;color:#fff}label{display:block;font-weight:700;margin-top:16px}input{display:block;width:100%;margin-top:5px;padding:11px;border:2px solid #52656c;border-radius:5px;color:#14252e;font:inherit}button{margin-top:20px;padding:11px 18px;border:0;border-radius:5px;background:#075d72;color:#fff;font:inherit;cursor:pointer}button:hover{background:#064e60}button:focus,input:focus,a:focus{outline:3px solid #e89722;outline-offset:3px}.notice{padding:13px;border-left:5px solid #075d72;background:#e5f3f5}.error{background:#fde9e8;border-left-color:#b42318}.hide{display:none}a{color:#064e60}.logs{margin-top:24px;padding:14px;background:#132a33;color:#e5f3f5;border-radius:7px}.logs h2{font-size:1rem;margin-bottom:7px}#logOutput{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.support{margin-top:23px}.small{font-size:.93rem}.recovery-link{margin-top:16px}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>Hospital account recovery</h1>
<ol class="progress" aria-label="Your recovery progress">
<li id="progress1" class="active">1. Start</li><li id="progress2">2. Verify</li><li id="progress3">3. New password</li><li id="progress4">4. Sign in</li>
</ol>
<p class="small">You can pause at any time. There is no session countdown.</p>
</header>
<main>
<div id="message" class="notice" role="status" aria-live="polite">Start when you are ready. We will guide you one step at a time.</div>

<section id="start">
<h2>Reset your password</h2>
<p>Enter your account email. If it matches an account, a recovery code will be sent in this demo.</p>
<label for="email">Email address</label><input id="email" type="email" autocomplete="email">
<button id="requestCode" type="button">Send recovery code</button>
</section>

<section id="verify" class="hide">
<h2>Check your recovery code</h2>
<p>A simulated code appears in the Logs panel. You can enter it below or use the recovery link.</p>
<div id="recoveryLinkArea" class="recovery-link"></div>
<label for="token">Recovery code</label><input id="token" autocomplete="one-time-code">
<button id="verifyCode" type="button">Verify code</button>
</section>

<section id="newPassword" class="hide">
<h2>Choose a new password</h2>
<p>Use 12 or more characters, including uppercase and lowercase letters, a number, and a symbol.</p>
<label for="password">New password</label><input id="password" type="password" autocomplete="new-password">
<label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" autocomplete="new-password">
<button id="savePassword" type="button">Save new password</button>
</section>

<section id="signIn" class="hide">
<h2>Sign in</h2><p>Your password was updated. Sign in when you are ready.</p>
<label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password">
<button id="loginButton" type="button">Sign in</button>
</section>

<section id="mfa" class="hide">
<h2>Confirm it is you</h2><p>A simulated verification code is shown in the Logs panel below.</p>
<label for="mfaCode">Verification code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code">
<button id="confirmMfa" type="button">Confirm and continue</button>
</section>

<section id="complete" class="hide">
<h2>You are signed in</h2><p class="notice">You can now accept the updated privacy statement before your appointment is booked.</p>
<button id="acceptPrivacy" type="button">Accept privacy statement</button>
</section>

<p class="support"><a id="helpLink" href="#help">Need help?</a></p>
<div id="helpText" class="notice hide" role="status">For safety, hospital staff will never ask for your password or recovery code. Pause here and contact the hospital using its known phone number if you need help.</div>

<section class="logs" aria-label="Demo logs"><h2>Logs</h2><pre id="logOutput">Waiting for a simulated delivery or verification event.</pre></section>
</main>
</div>

<script nonce="${nonce}">
/* Inclusivity: stable server-resumable steps, no timers in the UI, visible help. */
/* Security: no secrets in localStorage; DOM text APIs are used for all user-derived display. */
(function(){
  var csrf="", sections=["start","verify","newPassword","signIn","mfa","complete"];
  function byId(id){return document.getElementById(id)}
  function demoLog(message){console.log(message);var output=byId("logOutput");output.textContent=message+"\\n"+output.textContent}
  function setMessage(message,error){var n=byId("message");n.textContent=message;n.classList.toggle("error",Boolean(error))}
  function show(section,message,error){
    sections.forEach(function(name){byId(name).classList.toggle("hide",name!==section)});
    var step=sections.indexOf(section);
    ["progress1","progress2","progress3","progress4"].forEach(function(id,index){byId(id).classList.toggle("active",index===Math.min(step,3))});
    setMessage(message,error);
  }
  function renderRecoveryLink(token){
    var area=byId("recoveryLinkArea");area.replaceChildren();
    var p=document.createElement("p"), link=document.createElement("a");
    link.href=new URL("/?token="+encodeURIComponent(token),location.origin).href;
    link.textContent="Open your simulated recovery link";
    p.appendChild(link);area.appendChild(p);
  }
  async function api(path,data){
    var response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"content-type":"application/json"},body:JSON.stringify(Object.assign({},data,{csrf:csrf}))});
    return await response.json();
  }
  async function initialize(){
    var response=await fetch("/api/recovery-status",{credentials:"same-origin"});
    var data=await response.json();csrf=data.csrf;
    var token=new URLSearchParams(location.search).get("token");
    if(token && data.step==="verify"){byId("token").value=token;show("verify","Recovery link opened. Verify the code when you are ready.",false);return}
    var messages={start:"Start when you are ready. We will guide you one step at a time.",verify:"Continue by entering your recovery code.",newPassword:"Your code is verified. Choose your new password.",signIn:"Your password was updated. Sign in when you are ready.",mfa:"Continue by entering your verification code.",complete:"Identity confirmed. You are signed in."};
    show(data.step,messages[data.step]||messages.start,false);
  }

  byId("requestCode").addEventListener("click",async function(){
    var data=await api("/api/request-reset",{email:byId("email").value});
    if(!data.ok){show("start",data.message,true);return}
    if(data.token){
      var recoveryLink=new URL("/?token="+encodeURIComponent(data.token),location.origin).href;
      demoLog("SIMULATED recovery delivery. Code: "+data.token+" | Recovery link: "+recoveryLink);
      renderRecoveryLink(data.token);
    }
    show("verify",data.message,false);
  });
  byId("verifyCode").addEventListener("click",async function(){
    var data=await api("/api/verify-reset",{token:byId("token").value});
    if(!data.ok){show("verify",data.message,true);return}
    byId("token").value="";
    show("newPassword","Code verified. Now choose your new password.",false);
  });
  byId("savePassword").addEventListener("click",async function(){
    var data=await api("/api/reset-password",{password:byId("password").value,confirm:byId("confirmPassword").value});
    if(!data.ok){show("newPassword",data.message,true);return}
    byId("password").value="";byId("confirmPassword").value="";
    show("signIn","Password saved. Sign in when you are ready.",false);
  });
  byId("loginButton").addEventListener("click",async function(){
    var data=await api("/api/login",{password:byId("loginPassword").value});
    if(!data.ok){show("signIn",data.message,true);return}
    byId("loginPassword").value="";demoLog("SIMULATED MFA delivery. Verification code: "+data.code);
    show("mfa","Enter the verification code shown in the Logs panel.",false);
  });
  byId("confirmMfa").addEventListener("click",async function(){
    var data=await api("/api/mfa",{code:byId("mfaCode").value});
    if(!data.ok){show("mfa",data.message,true);return}
    byId("mfaCode").value="";demoLog("SIMULATED verification successful.");
    show("complete","Identity confirmed. You are signed in.",false);
  });
  byId("acceptPrivacy").addEventListener("click",async function(){
    var data=await api("/api/privacy",{});
    if(data.ok){demoLog("SIMULATED privacy statement acceptance recorded.");show("complete","Privacy statement accepted. Hospital authorities may now book your appointment.",false)}
    else show("complete","Please sign in again before accepting the privacy statement.",true);
  });
  byId("helpLink").addEventListener("click",function(event){event.preventDefault();byId("helpText").classList.toggle("hide")});
  initialize();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const { sid, session } = getSession(request);

    if (request.method === "GET" && url.pathname === "/") {
      const nonce = randomHex(16);
      return new Response(htmlPage(nonce), {
        headers: {
          ...securityHeaders(sid, nonce),
          "content-type": "text/html; charset=utf-8",
        },
      });
    }

    /* Safe non-secret recovery resume state. Tokens and passwords are never returned. */
    if (request.method === "GET" && url.pathname === "/api/recovery-status") {
      let step = session.recoveryStep;
      if (session.authenticated) step = "complete";
      else if (session.mfaCode && session.mfaExpiresAt && session.mfaExpiresAt > Date.now()) step = "mfa";
      else if (step === "mfa") step = "signIn";
      return responseJson({ csrf: session.csrf, step }, sid);
    }

    if (request.method !== "POST" || !url.pathname.startsWith("/api/")) {
      return responseJson({ ok: false, message: "Not found." }, sid, 404);
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return responseJson({ ok: false, message: "Invalid request." }, sid, 400);
    }

    if (!validCsrf(body, session)) {
      return responseJson({ ok: false, message: "Request could not be verified. Refresh and try again." }, sid, 403);
    }

    const data = body as Record<string, unknown>;

    if (url.pathname === "/api/request-reset") {
      cleanExpiredTokens();
      const email = normalizeEmail(data.email);
      if (email.length > 200 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return responseJson({ ok: false, message: "Enter a valid email address." }, sid, 400);
      }

      session.resetRequested = true;
      session.recoveryStep = "verify";
      const account = accountsByEmail.get(email);
      const genericMessage = "If that email matches an account, a recovery code has been sent in this demo.";

      /* Only recognized accounts receive a token; response stays generic for unknown email. */
      if (!account) return responseJson({ ok: true, message: genericMessage }, sid);

      const token = randomHex(32);
      resetTokens.set(token, {
        accountId: account.id,
        expiresAt: Date.now() + 15 * 60 * 1000,
        used: false,
        failures: 0,
        blockedUntil: 0,
      });
      return responseJson({ ok: true, message: genericMessage, token }, sid);
    }

    if (url.pathname === "/api/verify-reset") {
      cleanExpiredTokens();
      if (Date.now() < session.resetBlockedUntil) {
        return responseJson({ ok: false, message: blockedMessage(session.resetBlockedUntil) }, sid, 429);
      }

      const token = text(data.token, 100);
      const record = resetTokens.get(token);
      if (record && Date.now() < record.blockedUntil) {
        return responseJson({ ok: false, message: blockedMessage(record.blockedUntil) }, sid, 429);
      }

      if (!record || record.used || record.expiresAt < Date.now()) {
        session.resetFailures += 1;
        if (session.resetFailures >= 5) {
          session.resetFailures = 0;
          session.resetBlockedUntil = Date.now() + 5 * 60 * 1000;
        }
        return responseJson({ ok: false, message: "That code is not valid. Request a new one and try again." }, sid, 400);
      }

      if (record.failures >= 5) {
        record.failures = 0;
        record.blockedUntil = Date.now() + 5 * 60 * 1000;
        return responseJson({ ok: false, message: blockedMessage(record.blockedUntil) }, sid, 429);
      }

      session.resetFailures = 0;
      session.verifiedResetToken = token;
      session.recoveryStep = "newPassword";
      return responseJson({ ok: true }, sid);
    }

    if (url.pathname === "/api/reset-password") {
      cleanExpiredTokens();
      const password = rawString(data.password);
      const confirm = rawString(data.confirm);

      if (password === null || confirm === null) {
        return responseJson({ ok: false, message: "Enter your new password in both fields." }, sid, 400);
      }
      if (password.length > 300 || confirm.length > 300) {
        return responseJson({ ok: false, message: "Password entries must be 300 characters or fewer." }, sid, 400);
      }

      const token = session.verifiedResetToken;
      const record = token ? resetTokens.get(token) : undefined;
      if (!token || !record || record.used || record.expiresAt < Date.now()) {
        return responseJson({ ok: false, message: "Verify a current recovery code first." }, sid, 403);
      }

      const account = accountsById.get(record.accountId);
      if (!account) {
        return responseJson({ ok: false, message: "Verify a current recovery code first." }, sid, 403);
      }

      if (!passwordIsStrong(password) || !safeEqual(password, confirm)) {
        return responseJson({ ok: false, message: "Use the stated password rules and make both password entries match." }, sid, 400);
      }

      /* Token-bound update: only the intended account record is changed. */
      account.passwordHash = await Bun.password.hash(password, { algorithm: "argon2id" });
      record.used = true;
      resetTokens.delete(token);
      session.verifiedResetToken = undefined;
      session.recoveryStep = "signIn";
      return responseJson({ ok: true }, sid);
    }

    if (url.pathname === "/api/login") {
      if (Date.now() < session.loginBlockedUntil) {
        return responseJson({ ok: false, message: blockedMessage(session.loginBlockedUntil) }, sid, 429);
      }

      const password = rawString(data.password);
      if (password === null || password.length > 300) {
        return responseJson({ ok: false, message: "Password not accepted. Check it and try again." }, sid, 401);
      }

      const accepted = await Bun.password.verify(password, helenaAccount.passwordHash);
      if (!accepted) {
        session.loginFailures += 1;
        if (session.loginFailures >= 5) {
          session.loginFailures = 0;
          session.loginBlockedUntil = Date.now() + 5 * 60 * 1000;
        }
        return responseJson({ ok: false, message: "Password not accepted. Check it and try again." }, sid, 401);
      }

      session.loginFailures = 0;
      session.mfaFailures = 0;
      session.mfaCode = "246810";
      session.mfaExpiresAt = Date.now() + 5 * 60 * 1000;
      session.authenticated = false;
      session.recoveryStep = "mfa";
      return responseJson({ ok: true, code: session.mfaCode }, sid);
    }

    if (url.pathname === "/api/mfa") {
      if (Date.now() < session.mfaBlockedUntil) {
        return responseJson({ ok: false, message: blockedMessage(session.mfaBlockedUntil) }, sid, 429);
      }

      const code = text(data.code, 20);
      if (!session.mfaCode || !session.mfaExpiresAt || session.mfaExpiresAt < Date.now()) {
        session.mfaCode = undefined;
        session.mfaExpiresAt = undefined;
        session.recoveryStep = "signIn";
        return responseJson({ ok: false, message: "That verification code has expired. Sign in again to receive a new code." }, sid, 401);
      }

      if (!safeEqual(code, session.mfaCode)) {
        session.mfaFailures += 1;
        if (session.mfaFailures >= 5) {
          session.mfaFailures = 0;
          session.mfaBlockedUntil = Date.now() + 5 * 60 * 1000;
        }
        return responseJson({ ok: false, message: "That verification code is not correct." }, sid, 401);
      }

      session.mfaFailures = 0;
      session.authenticated = true;
      session.mfaCode = undefined;
      session.mfaExpiresAt = undefined;
      session.recoveryStep = "complete";
      return responseJson({ ok: true }, sid);
    }

    if (url.pathname === "/api/privacy") {
      if (!session.authenticated) {
        return responseJson({ ok: false, message: "Authentication required." }, sid, 403);
      }
      return responseJson({ ok: true }, sid);
    }

    return responseJson({ ok: false, message: "Not found." }, sid, 404);
  },
});

console.log(`Hospital recovery portal running at https://localhost:${server.port}`);
