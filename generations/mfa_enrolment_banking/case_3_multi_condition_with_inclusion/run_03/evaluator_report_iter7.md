## SUMMARY

The artifact is a single-file Bun SPA with a functional MFA enrolment flow, HTTPS configuration, session ownership checks, CSRF protection, OTP simulation, QR/manual authenticator setup, recovery-code generation, and mobile-oriented styling. However, it does not fully meet the security requirements because it logs OTP secrets and recovery codes even in production mode, and it retains plaintext recovery codes in server memory.

## FUNCTIONAL_CHECK

- **Single-file Bun application with inline HTML, CSS, JavaScript, and TLS support — PASS**  
  The application is contained in `app.ts`, uses `Bun.serve`, reads the required TLS certificate files, and serves inline HTML/CSS/client JavaScript without frameworks, bundlers, or external assets.

- **Responsive, mobile-friendly, dyslexia-aware enrolment UI — PASS**  
  The UI uses a constrained mobile layout, generous spacing, legible font sizing, plain wording, step indicators, examples for OTP inputs, visual status messages, and no moving or flashing content.

- **Functional enrolment flow: sign-in, identity verification, authenticator setup, recovery-code storage — PASS**  
  The client flow supports sign-in, requesting/re-requesting an identity code, verifying it, generating authenticator setup details, QR/manual setup, OTP confirmation, recovery-code copying/regeneration, and completion.

- **Mock OTPs and recovery codes are available in the browser console for academic testing — PASS**  
  In academic mock mode, identity OTPs, provisioning URI, TOTP values, authenticator secrets, and recovery codes are returned to the UI flow and sent to browser `console.log`.

- **Manual authenticator provisioning support — PASS**  
  The provisioning URI and manual setup key are visibly available, can be copied, and the user can submit an authenticator code manually after configuring an authenticator.

- **Server-side authorization and IDOR protection — PASS**  
  MFA endpoints derive the account from the authenticated session and do not accept a user identifier from the client. Requests are bound to the session owner.

- **CSRF protection for state-changing requests — PASS**  
  A boot CSRF token is used before sign-in, a session-bound CSRF token is used after sign-in, and POST endpoints validate the token.

- **Secure headers, TLS, secure cookies, restricted CORS, and generic server errors — PASS**  
  The server configures TLS, HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Secure; HttpOnly; SameSite=Strict` cookies, trusted-origin CORS behavior, and generic catch-all errors.

- **No sensitive data in logs — FAIL**  
  The browser client logs provisioning URIs, authenticator secrets, current TOTPs, and recovery codes regardless of whether `MFA_MODE=production`. This directly violates the requirement that OTP seeds, OTPs, and backup codes must never appear in logs. The server comment claims production suppresses mocks, but the client does not implement that suppression.

- **OTP-secret and recovery-code protection at rest — FAIL**  
  The authenticator seed is encrypted with AES-GCM, and account recovery codes are stored as hashes in `u.recovery`. However, every generated recovery code is also retained in plaintext in the global `issuedRecoveryCodes` set. This leaves backup codes stored in readable server memory and violates the requirement to store recovery codes using strong hashing/encryption at rest.

- **OTP validity, single-use enforcement, failed-attempt controls, and session lifecycle — PASS**  
  Identity codes expire and are single use. TOTP verification permits a narrow time window and records used time steps to prevent reuse. Identity, authenticator, and recovery-code verification attempts have lockouts after repeated failures. Sessions are rotated on sign-in, have idle/absolute expiry, and can be invalidated through logout.

- **Input validation and output escaping — PASS**  
  Email, password length, OTP, and recovery-code formats are validated server-side. Client-rendered dynamic values are escaped before insertion into HTML, and the API only accepts structured JSON objects.

- **No external network calls or build tools — PASS**  
  The application has no external fetches or imported frontend dependencies. The QR generator is implemented inline.

## FAILING_ITEMS

- **Sensitive authenticator material is logged in production mode.**  
  In the authenticator setup flow, the following calls execute whether mock mode is enabled or not:
  - `log("Mock provisioning URI:",uri)`
  - `log("Mock authenticator secret:",secret)`
  - `log("Mock recovery codes:",codes.join(", "))`
  - `log("Mock replacement recovery codes:",codes.join(", "))`

  These expose OTP seeds, provisioning data, and backup codes in browser console logs in production.

- **The `issuedRecoveryCodes` global stores raw recovery codes indefinitely.**  
  `newRecoverySet()` adds each plaintext recovery code to `issuedRecoveryCodes`. Although the per-user recovery set stores hashes, this global plaintext set is still a sensitive at-rest copy.

## NEW_TASKS

1. Wrap all browser logging of identity codes, provisioning URIs, authenticator secrets, TOTPs, and recovery codes in an `if (mock)` condition so that sensitive values are logged only in academic mock mode.

2. Remove the plaintext global `issuedRecoveryCodes` set and its writes. Rely on cryptographically secure random generation for production recovery-code uniqueness, or store only hashes if collision tracking is required.

3. Update the production-mode UI/log wording so it does not label real provisioning values as “Mock” and does not imply that sensitive setup material is being logged.

## DECISION

**FAIL**