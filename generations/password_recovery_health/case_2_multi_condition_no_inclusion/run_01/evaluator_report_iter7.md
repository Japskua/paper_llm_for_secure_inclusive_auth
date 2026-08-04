## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functional password-recovery, reset, MFA, login, and privacy-acceptance flow. It has strong session binding, CSRF protection, secure headers, bcrypt password hashing, short-lived single-use recovery tokens, and browser-console mock delivery logging. However, the recovery-request rate limiter is invoked but its result is ignored, so repeated recovery requests are never actually throttled or blocked. This prevents full compliance with the throttling requirement.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact with Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The application, HTML template, CSS, client JavaScript string, and Bun server are all contained in `app.ts`.
  - No frameworks, build tools, compilation steps, or external network assets are used.

- **Bun TLS server uses the required certificate paths: PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - Requests whose URL protocol is not HTTPS are rejected.

- **SPA routing and internal links function: PASS**
  - Hash routes exist for recovery, factor verification, reset, sign-in, MFA, privacy, and confirmation.
  - The simulated reset link routes to `/?code=...#verify`.
  - Manual recovery-code submission is supported.

- **Recovery delivery mocks appear in the browser console: PASS**
  - Recovery tokens and MFA test codes are returned by the server only for this deterministic demo flow.
  - The client logs these values through `console.log(...)` in the browser as required.

- **Recovery token security: PASS**
  - Tokens are generated with cryptographically secure random bytes.
  - Tokens are session-bound, expire after 10 minutes, are marked used after verification, and cannot be reused.
  - Verification uses timing-safe comparison and input-format validation.

- **CSRF protection on sensitive requests: PASS**
  - A random CSRF token is created per session.
  - All POST API routes require a matching `X-CSRF-Token`.
  - The token is session-bound and protected from cross-origin reading by browser same-origin policy.

- **Session and access control protections: PASS**
  - Sessions use random identifiers in `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` cookies.
  - Sensitive actions require the associated session and appropriate recovery/authentication state.
  - Privacy acceptance requires MFA-authenticated state.
  - No user names, patient identifiers, course folders, or account identifiers are returned or displayed.

- **XSS and injection handling: PASS**
  - User-controlled values are not interpolated into server-rendered HTML.
  - Client-side rendering uses static templates; untrusted data is not injected into `innerHTML`.
  - Log output is assigned through `textContent`.
  - The CSP restricts scripts to same-origin resources and uses a nonce for the style block.

- **Security headers and production-safe errors: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, no-cache headers, and COOP are configured.
  - Error responses are generic and do not expose stack traces or debug details.

- **Password policy and secure password storage: PASS**
  - Passwords require 12–128 characters, upper/lowercase letters, a number, and a symbol.
  - Passwords are bcrypt-hashed using Bun’s password API with bcrypt cost 12.
  - Plaintext passwords are not stored in session state.

- **MFA implementation: PASS**
  - Password reset and sign-in both require a second MFA verification step before authentication is completed.
  - The deterministic MFA code is explicitly presented as an evaluation mock and logged in the browser.

- **Login, recovery-factor, recovery-code, reset-password, and MFA brute-force protections: PASS**
  - These sensitive verification routes enforce a per-client/per-session attempt limit and return `429` after the configured maximum attempts.

- **Recovery-request throttling/blocking: FAIL**
  - `/api/recovery/request` calls `allowed("request", request, "generic", 3)` but ignores the returned boolean.
  - Even after the configured limit is exceeded, the endpoint continues returning a successful response rather than blocking or throttling the request.
  - This is contrary to the requirement that automated attempts be throttled or blocked.

- **Safe-authentication guidance and anti-social-engineering messaging: PASS**
  - The interface tells users not to share passwords or verification codes by email, phone, text, or similar channels.
  - No outgoing URLs, redirects, external delivery services, or support impersonation paths are implemented.

## FAILING_ITEMS

- **Recovery request rate limiting is ineffective.**
  - In `/api/recovery/request`, the return value of `allowed(...)` is discarded:
    ```ts
    allowed("request", request, "generic", 3);
    return reply({ ok: true, ... });
    ```
  - As a result, requests beyond the intended three-per-15-minute limit are still accepted with HTTP 200.
  - This should return a throttling response, such as HTTP 429, once the rate limit is exceeded.

## NEW_TASKS

1. Update `/api/recovery/request` to check the return value of `allowed("request", request, "generic", 3)` and return a `429` response with a generic, non-enumerating message when the limit is exceeded.

## DECISION

FAIL