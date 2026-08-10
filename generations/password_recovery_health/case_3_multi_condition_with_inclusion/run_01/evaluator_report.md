## SUMMARY

The artifact is a valid single-file Bun application that serves a TLS-protected password-recovery SPA with inline HTML, CSS, and vanilla browser JavaScript. The recovery, manual token entry/link flow, password update, post-reset sign-in, MFA, and privacy acceptance flow are implemented and functionally connected. Security controls including per-session CSRF tokens, CSP nonces, secure headers, random expiring single-use reset tokens, Argon2id hashing, rate limiting, and authenticated privacy acceptance are present. No concrete functional, security, or compilation-blocking errors were identified.

## FUNCTIONAL_CHECK

- **PASS — Single `app.ts` deliverable with Bun server, HTML, CSS, and client JavaScript.**  
  The server and complete SPA template are contained in one TypeScript file. It uses `Bun.serve` directly and requires no bundler, framework, external assets, or compilation pipeline.

- **PASS — Bun TLS server uses the specified certificate paths.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the startup URL uses `https://localhost`.

- **PASS — Password-reset journey is complete and connected.**  
  The UI supports: reset request → token delivery → token verification → new password → sign-in → MFA → authenticated privacy acceptance. The corresponding API routes are implemented and update server-side recovery state.

- **PASS — Recovery token can be submitted manually and through a recovery link.**  
  The token is displayed in browser console/UI logs, may be manually entered in the recovery-code field, and is included in a generated same-origin recovery link. Opening the link fills the token field and directs the user to the verification step.

- **PASS — Simulated delivery information is logged in the browser.**  
  Recovery delivery is returned by the server for the demo and passed to the client, where `demoLog()` calls browser `console.log`. MFA code delivery and completion/privacy simulation events are also logged in the browser.

- **PASS — Reset tokens are cryptographically random, expiring, and single-use.**  
  Reset tokens are generated with `crypto.getRandomValues`, expire after 15 minutes, and are removed from `resetTokens` immediately after successful verification. New requests invalidate the prior session delivery token.

- **PASS — Reset grants are protected and short-lived.**  
  After token verification, a separate random reset grant is issued, bound to the current session ID, expires after 10 minutes, and is consumed when the password is changed.

- **PASS — CSRF protection is implemented for sensitive requests.**  
  Each session receives a random CSRF value. All `POST /api/*` operations require a matching CSRF token in the JSON body through `validCsrf()`.

- **PASS — Session cookies have appropriate browser protections.**  
  The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.

- **PASS — Secure headers and HTTPS protections are configured.**  
  Responses include HSTS, CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, restrictive referrer and permissions policies, and `Cache-Control: no-store`.

- **PASS — CSP protects against unauthorized script execution.**  
  The HTML uses a unique nonce for the inline style and script elements. CSP permits only nonce-authorized scripts/styles and limits connection, form, framing, base URI, and image sources to safe values.

- **PASS — User-controlled values are not inserted into the DOM as HTML.**  
  Client-side display uses `textContent`, `replaceChildren`, and DOM element creation rather than `innerHTML`. Server responses do not interpolate user-controlled content into HTML.

- **PASS — Password policy is enforced server-side.**  
  Passwords must be at least 12 characters and contain uppercase, lowercase, numeric, and symbol characters. Confirmation is checked with constant-time comparison.

- **PASS — Passwords are hashed using Argon2id.**  
  Updated passwords are stored using `await Bun.password.hash(password, { algorithm: "argon2id" })`; plaintext passwords are not stored.

- **PASS — Login and MFA attempts are throttled.**  
  Reset requests, reset-token verification, login attempts, and MFA verification are rate-limited with temporary blocking after repeated failed/excessive attempts.

- **PASS — MFA is implemented in the simulated flow.**  
  After successful post-reset sign-in, the server issues a short-lived MFA code. MFA must succeed before the session is marked authenticated and privacy acceptance is permitted.

- **PASS — Sensitive action access control is enforced.**  
  Password resetting requires a valid session-bound reset grant. Login is restricted to the account successfully reset in that same session. Privacy acceptance requires `session.authenticated === true`.

- **PASS — Account enumeration is mitigated during reset request.**  
  The reset-request response message does not reveal whether an account exists. A simulated delivery is prepared uniformly for valid email-shaped input.

- **PASS — No external network calls, open redirects, or third-party assets are present.**  
  Client requests are same-origin API calls only. Generated recovery URLs are fixed to `location.origin` and a fixed same-origin path.

- **PASS — ADHD/inclusivity requirements are addressed.**  
  The flow has visible progress, one active step at a time, clear next-step messaging, browser-resumable server state, no client countdowns, a visible “pause” reassurance, and accessible help at every stage.

- **PASS — Internal navigation functions.**  
  The help link toggles contextual help without navigation. Recovery links are same-origin and correctly restore the verification UI with the token populated.

- **PASS — Error handling avoids debug/stack-trace exposure.**  
  API responses provide generic actionable messages. The browser handles fetch failures, malformed responses, and non-JSON replies without exposing server internals.

- **PASS — Code validation / runtime structure.**  
  The TypeScript structure, Bun APIs, route handling, response construction, session handling, nonce handling, and client-side event wiring are internally consistent. No apparent syntax, type, or route-flow errors prevent the application from running under Bun 1.3.0.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

PASS