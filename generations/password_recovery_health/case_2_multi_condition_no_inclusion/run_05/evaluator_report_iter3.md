## SUMMARY

The artifact is a well-structured single-file Bun application with a functional password recovery flow, TLS startup enforcement, secure session cookies, CSRF validation, throttling, CSP/security headers, bcrypt password hashing, MFA simulation, and browser-console mock delivery logs. However, token verification has a concrete runtime error path: a syntactically valid token of a different length than the stored token can cause `crypto.timingSafeEqual` to throw, returning a generic `503 Service unavailable` rather than a controlled verification failure. Therefore, the artifact cannot be accepted as fully error-free.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` Bun server plus HTML/CSS/vanilla client JavaScript:** **PASS**  
  The server, HTML template, CSS, and browser-side JavaScript are all contained in the provided `app.ts`. No framework, bundler, compiler, or external asset is used.

- **Bun server uses the supplied TLS certificate paths and refuses plaintext portal startup without certificates:** **PASS**  
  The code checks `certs/cert.pem` and `certs/key.pem`, exits if either is absent, starts the portal with `tls`, and provides an HTTP-to-HTTPS redirect listener.

- **HTTPS enforcement and secure response headers:** **PASS**  
  HTTPS is enforced through TLS-only primary service and a `308` redirect service. The HTTPS response includes HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, restrictive referrer and permissions policies, and no-store caching headers.

- **CSRF prevention with unique session token and validation on sensitive requests:** **PASS**  
  A cryptographically random CSRF token is generated per server session. Every state-changing `/api/*` POST requires a valid token, and the code also validates the request `Origin`.

- **Secure session handling and access control:** **PASS**  
  Session IDs are random, server-side, `HttpOnly`, `Secure`, `SameSite=Strict`, and use a valid `__Host-` cookie configuration. Sensitive privacy and appointment actions check server-owned authentication, privacy acceptance, and phase state.

- **No user/patient/private identifier exposure:** **PASS**  
  The UI does not display account identities, patient data, appointment identifiers, or private account metadata. Recovery messaging is generic for valid and invalid account input.

- **XSS/injection resistance:** **PASS**  
  User input is validated server-side, and client-side rendering uses DOM APIs with `textContent` and `replaceChildren` rather than unsafe HTML insertion. No user-controlled value is inserted through `innerHTML`.

- **CSP and script restrictions:** **PASS**  
  The application uses a per-response nonce for both the inline style and application script, and the CSP disallows untrusted script sources and external connections.

- **Reset token requirements: random, short-lived, and single-use:** **FAIL**  
  Tokens are random, have a 10-minute expiry, and are marked used after successful verification. However, token comparison can throw for a valid-format token whose byte length differs from the stored token, producing a `503` instead of a safe invalid-token response.

- **Manual reset-code submission and simulated delivery:** **PASS**  
  The recovery token can be entered manually in the token form. The generated reset token is returned to the browser UI flow and logged through browser-side `console.log`. MFA is also simulated and manually submitted.

- **MFA or SSO:** **PASS**  
  A second-factor MFA step is implemented after reset-token verification. The MFA mock value is deterministic as required for testability.

- **Brute-force mitigation / throttling:** **PASS**  
  Recovery, token, MFA, password reset, and sign-in operations use per-session failure counters and temporary blocking after five failed attempts.

- **Password policy and password storage:** **PASS**  
  Passwords require at least 12 characters, upper/lowercase letters, numbers, and symbols; confirmation is required; some common/repetitive passwords are rejected. Passwords are hashed with Bun bcrypt and plaintext passwords are not stored or logged.

- **Phishing/social-engineering safeguards:** **PASS**  
  The UI includes anti-phishing guidance stating that passwords are never requested by email or support contact and instructs users to verify the local hospital address.

- **No external network calls or open redirects:** **PASS**  
  Client requests are same-origin `/api/*` calls only. The only redirect is a fixed local HTTP-to-HTTPS redirect; no user-controlled redirect URL exists.

- **Internal flow navigation/functions:** **PASS**  
  The recovery, token, MFA, password reset, sign-in, privacy acceptance, appointment request, and completion stages are implemented and transition through server-validated state.

- **Production error behavior:** **PASS**  
  The top-level handler catches unexpected errors and returns a generic service-unavailable message without stack traces or debug information.

## FAILING_ITEMS

- **Token comparison can trigger an exception for a malformed-length but regex-valid token.**  
  In `verify-token`, `validToken(body.token)` permits Base64URL tokens from 32 to 128 characters, while `session.resetToken` is generated at a fixed length (normally 43 characters for 32 random bytes encoded as Base64URL). `crypto.timingSafeEqual(...)` requires operands of identical byte length. For example, a 32-character Base64URL token passes `validToken` but causes `timingSafeEqual` to throw when compared to the 43-character stored token.

- **The exception is converted into an incorrect `503 Service unavailable` response instead of a controlled verification failure.**  
  Because the exception reaches the outer `handler` catch block, the user receives a generic server failure rather than “That recovery code cannot be verified.” This bypasses the intended failed-attempt accounting for that request and does not provide the required clear invalid-token feedback.

## NEW_TASKS

1. In the `verify-token` action, compare the submitted token length to `session.resetToken.length` before calling `crypto.timingSafeEqual`; treat unequal lengths as an ordinary invalid token attempt.

2. Ensure all invalid token values, including valid-format values with a wrong length, call `failedAttempt(session, "token")` and return the normal invalid-token response rather than allowing an exception to reach the top-level error handler.

## DECISION

**FAIL**