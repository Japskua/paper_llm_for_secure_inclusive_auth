## SUMMARY

The artifact is a well-structured single-file Bun HTTPS SPA with functional recovery, token verification, password policy enforcement, bcrypt hashing for replacement passwords, MFA simulation, CSRF validation, secure cookies, authorization checks, and security headers. However, it does not fully meet the security requirements because the recovery endpoint leaks account-existence information through its response shape/UI behavior, and an initial password is embedded in plaintext in the server source.

## FUNCTIONAL_CHECK

- **Broken Access Control / CSRF protection — PASS**
  - Sessions use cryptographically random IDs, `HttpOnly`, `Secure`, `SameSite=Strict`, and `__Host-` cookie semantics.
  - Sensitive POST routes require both a same-origin `Origin` header and a per-session CSRF token.
  - Privacy acceptance and appointment confirmation enforce server-side authenticated-state checks.
  - No user-controlled object IDs are accepted for sensitive account actions, mitigating IDOR.

- **Injection / XSS protections — PASS**
  - Client-rendered dynamic content is inserted using `textContent`, not `innerHTML`.
  - The UI does not inject user input into HTML, script contexts, URLs without encoding, or server-rendered template interpolation.
  - CSP restricts resources and permits only the nonce-bearing application script.
  - No external assets or third-party scripts are loaded.

- **Security Misconfiguration / HTTPS / reset-token protections — PASS**
  - Bun serves HTTPS using `certs/cert.pem` and `certs/key.pem`.
  - HTTP requests are redirected only for approved local hosts and redirect to a fixed configured HTTPS origin.
  - HSTS, CSP, `X-Content-Type-Options`, clickjacking protection, referrer policy, permissions policy, and no-store caching headers are configured.
  - Reset tokens are random, server-side hashed, session/account-bound, short-lived, and single-use.
  - Verified reset grants are separately generated, hashed, short-lived, and single-use.
  - Unexpected hosts are rejected and redirects are not derived from attacker-controlled `Host` values.

- **Authentication and password-reset controls — FAIL**
  - Password replacement is bcrypt-hashed, password policy is enforced, reset verification is limited, and MFA attempts are limited.
  - However, the source contains an initial plaintext password: `"InitialMockOnly!2025"`. The requirement states that passwords must never be stored in plaintext. Even though it is immediately hashed at startup, it is still stored as plaintext in `app.ts`.
  - The reset request behavior is not genuinely account-enumeration resistant. A matching account receives a `testToken`, which makes the UI display a verification link and log a token; non-matching accounts receive neither. An attacker can distinguish whether an account exists by inspecting the JSON response or UI behavior despite the generic message.

- **SSRF, open redirect, and social-engineering protections — PASS**
  - Redirect destinations are fixed to the configured HTTPS origin rather than constructed from request input.
  - There are no outgoing network calls or user-controlled outbound URLs.
  - The UI includes clear warnings not to share passwords or verification codes with staff, phone callers, or email contacts.

- **Recovery flow and UX — PASS**
  - The flow is functional: request reset → obtain simulated browser-delivered token → verify via link or manual entry → set strong password → complete MFA → accept privacy statement → confirm appointment.
  - The reset token is shown in the browser log and can be manually submitted, as required.
  - The password reset link works through `/reset?token=...` and retains the session cookie necessary for verification.
  - Error messages are clear for expired grants, invalid tokens, invalid passwords, and authorization failures.

- **Single-file and zero-compilation compliance — PASS**
  - The server, HTML, CSS, and browser JavaScript are contained in one `app.ts` file.
  - It uses Bun directly with no framework, build tool, bundler, compiler, or external assets.

- **Code validity / runtime concerns — PASS**
  - The TypeScript/Bun APIs used are compatible with the intended Bun runtime model, including top-level `await`, `Bun.serve`, TLS configuration, and `Bun.password.hash`.
  - Route handling, JSON parsing, cookie parsing, token comparison, and cleanup logic are internally consistent.

## FAILING_ITEMS

- **Plaintext password is present in source code**
  - `mockAccount.passwordHash` is initialized by hashing the literal `"InitialMockOnly!2025"` at runtime.
  - This violates the stated requirement that passwords must never be stored in plaintext, since the plaintext password is retained in the application source.

- **Recovery endpoint leaks whether the submitted email matches the configured account**
  - `/api/request-reset` only includes `testToken` when `accountMatches` is true.
  - The client only renders the “Open the secure verification link” link when `result.testToken` exists.
  - Therefore, an attacker can submit candidate email addresses and determine whether an account exists by inspecting either the response JSON or rendered UI, despite the generic success message.
  - This contradicts the stated privacy claim in the UI and weakens the requirement to avoid exposing private account identifiers/account existence.

## NEW_TASKS

1. Replace the plaintext initial password literal with a precomputed bcrypt hash constant, so no plaintext password value exists in `app.ts` at runtime or in source.

2. Make reset-request responses and UI behavior indistinguishable for matching and non-matching email addresses.
   - Return an identically shaped simulated response for both cases.
   - Ensure the UI always displays the same post-request state.
   - If a test token must be shown for testing, use an explicit test-only mode or a non-account-enumerating deterministic simulation mechanism that does not reveal whether the submitted email matched an account.

3. Update the recovery-request explanatory text so it accurately reflects the implemented behavior after the enumeration fix.

## DECISION

**FAIL**