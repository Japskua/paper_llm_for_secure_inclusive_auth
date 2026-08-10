## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with responsive mobile UI, inline vanilla JavaScript, server-side sessions, CSRF checks, TLS configuration, security headers, encrypted OTP secrets, hashed recovery codes, and working enrolment/recovery flows. However, it does not fully meet the security requirements: it treats any syntactically valid email/phone pair as Marcus’s authenticated account, and it logs the authenticator seed in the browser console despite the explicit prohibition on logging OTP seeds. Rate limiting also does not count malformed verification submissions and can be bypassed by starting new sessions.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` implementation with Bun server, inline HTML/CSS/JS, no frameworks/build tools/external assets: PASS**
  - The complete server and client application are in one `app.ts` file.
  - It uses `Bun.serve`, inline HTML/CSS/JavaScript, and no external network calls, packages, bundlers, or frameworks.

- **HTTPS/TLS server using supplied certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - HTTP is not separately served.

- **Mobile-responsive, legible SPA UI: PASS**
  - The page includes a viewport meta tag.
  - The layout uses a constrained mobile-friendly main column, large inputs/buttons, responsive flex actions, and readable typography.

- **End-to-end MFA enrolment flow works: PASS**
  - The UI supports sign-in, identity verification, authenticator provisioning, manual secret confirmation, authenticator OTP verification, recovery-code display, settings, recovery-code validation, regeneration, and logout.
  - The mock identity OTP, authenticator OTP, and recovery codes are returned to the UI and logged in the browser console.

- **Manual authenticator setup is available when a provisioning URI is offered: PASS**
  - The setup page displays both a manual setup secret and an `otpauth://` provisioning value.
  - The user can submit the manual secret and mock OTP to complete setup.

- **Recovery codes are generated securely, stored as protected values, and consumed once: PASS**
  - Recovery codes use `crypto.getRandomValues`.
  - Persisted values are SHA-256 hashes combined with a server-side pepper.
  - The server clears `pendingRecoveryDisplay` before responding, limiting plaintext display to one retrieval.
  - A verified recovery code is removed from `recoveryHashes`, making it single-use.

- **OTP secret is protected at rest: PASS**
  - The authenticator secret is stored using AES-GCM encryption with a randomly generated master key.
  - OTPs are computed on demand and not persisted.

- **Server-side authorization and IDOR protection: FAIL**
  - `/api/signin` accepts any syntactically valid email address and phone number, then creates a session with `account: "marcus"`.
  - There is no server-side association between the submitted identity details and the Marcus account.
  - Consequently, any visitor can submit arbitrary valid contact details, receive the mock verification code, and obtain an authenticated Marcus MFA session.
  - Although user-controlled account identifiers are not exposed in MFA routes, account ownership is not actually enforced.

- **CSRF protection for state-changing requests: PASS**
  - POST state-changing routes require a CSRF token tied to the server-side session.
  - The session cookie is also `SameSite=Strict`.
  - MFA enablement, recovery validation, recovery regeneration, sign-in, and logout all require CSRF validation.

- **Secure session-cookie configuration and lifecycle: PASS**
  - Cookies are set with `HttpOnly`, `Secure`, `SameSite=Strict`, and a restricted path.
  - Session IDs are opaque random values.
  - Session IDs rotate after sign-in.
  - Idle and absolute session expiry are enforced server-side.
  - Logout removes the server session and expires the browser cookie.

- **Secure response headers and restricted CORS: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, Referrer Policy, and Permissions Policy are included.
  - CORS is limited to localhost trusted origins and credentials are enabled only for trusted origins.
  - Generic errors are returned without stack traces.

- **No secrets in logs, URLs, or errors: FAIL**
  - The client calls:
    ```js
    log("Mock authenticator secret: " + data.secret);
    ```
  - This places the OTP shared secret/seed in the browser console and in the in-page Logs panel.
  - The requirements explicitly prohibit exposing OTP seeds in logs.
  - Logging the mock authenticator OTP is sufficient for evaluation; logging the seed is unnecessary.

- **Input validation, XSS protections, and redirect restrictions: PASS**
  - Server-side validators are present for email, phone, OTP, setup secret, and recovery-code formats.
  - UI output uses `textContent` rather than HTML insertion.
  - Redirect input is restricted to an internal allow-list.
  - No database queries are present, so SQL injection is not applicable to this in-memory mock implementation.

- **Verification codes are time-bound and single-use: PASS**
  - Identity codes have a five-minute expiry and `used` flag.
  - Authenticator setup confirmation can only succeed once because the flow advances from `provisioned` to `mfa`.
  - Recovery codes are consumed after successful validation.
  - Mock TOTP values are time-based.

- **Failed verification attempt rate limiting and lockout: FAIL**
  - Lockout applies only after five failures that pass input format validation.
  - Invalid-format OTP/recovery submissions return early and do not increment the failure counter:
    ```ts
    if (... || !validOtp(body.otp) || !mayAttempt(...)) {
      return genericError(400, request);
    }
    ```
  - An attacker can repeatedly send malformed values without contributing to lockout.
  - Identity-verification lockout is also tied only to an individual session, and a new anonymous session can be created repeatedly to obtain a new challenge and bypass prior session lockout.

## FAILING_ITEMS

- Any syntactically valid email and phone number can authenticate as the hardcoded `"marcus"` account. The server does not verify that submitted identity data belongs to Marcus before granting an authenticated MFA session.

- The authenticator shared secret is explicitly logged to the browser console and displayed in the Logs panel through:
  ```js
  log("Mock authenticator secret: " + data.secret);
  ```
  This violates the requirement not to expose OTP seeds in logs.

- Failed-attempt counting is bypassed by malformed OTP and recovery-code requests because validation failures do not increment attempt counters.

- Identity-verification lockout is per session only and is easily avoided by discarding the session and beginning a new sign-in flow.

## NEW_TASKS

1. Replace the unconditional `account: "marcus"` assignment in `/api/signin` with a server-side mock account lookup that verifies the submitted email/phone pair belongs to the Marcus mock account before creating an account-bound identity-verification session. Return the same generic response for invalid and valid identities to avoid user enumeration.

2. Remove the client-side authenticator-seed log statement:
   ```js
   log("Mock authenticator secret: " + data.secret);
   ```
   Continue rendering the secret in the protected setup UI for manual configuration, but log only the mock authenticator OTP needed for evaluation.

3. Refactor identity, authenticator, and recovery verification failure handling so malformed submitted verification values count as failed attempts and are subject to the same five-attempt lockout behavior.

4. Add a server-side lockout/rate-limit record associated with the mock account and/or validated identity target, rather than only the current session, so restarting a session cannot bypass repeated identity-verification failures.

## DECISION

FAIL