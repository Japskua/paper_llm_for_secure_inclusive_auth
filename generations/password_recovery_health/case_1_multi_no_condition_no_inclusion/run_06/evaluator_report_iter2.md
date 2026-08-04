## SUMMARY

The artifact satisfies the single-file Bun HTTPS SPA requirement and implements a functional password-recovery, password-reset, login, MFA, and privacy-acceptance flow. It uses server-side sessions, per-session CSRF validation, HTTPS/TLS, security headers, bcrypt password hashing, rate limiting, reset-token expiry/single use, and browser-side safe DOM handling. The TypeScript and browser JavaScript appear syntactically valid for Bun 1.3.0, with no external dependencies, build tooling, or network calls.

## FUNCTIONAL_CHECK

- **PASS — Single-file application and zero-compilation compliance:**  
  The server, HTML template, CSS, browser JavaScript, and backend logic are all contained in `app.ts`. It runs directly through Bun with no bundler, framework, package dependency, external asset, or compilation step.

- **PASS — Bun HTTPS server uses supplied TLS certificates:**  
  The server reads `certs/cert.pem` and `certs/key.pem` and starts `Bun.serve` with `tls: { cert, key }`. This meets the required localhost TLS setup.

- **PASS — Password-reset request flow works without account enumeration:**  
  `/api/reset/request` returns the same generic message for valid, invalid, and unknown contacts. The registered contact is never returned to the client. For the valid simulated account, a reset token is returned only as the required training mock value.

- **PASS — Mock delivery is shown in the UI and logged in the browser:**  
  The reset token is displayed in the training UI and logged via browser `console.log` through `addLog`. The simulated reset-link fragment is also logged. MFA mock codes are likewise logged in the browser.

- **PASS — Manual reset-code submission is supported:**  
  The verification view has a reset-code field, accepts manual submission, and calls `/api/reset/verify`. The fragment route parser also prepopulates a valid token from `#verify?token=...`.

- **PASS — Reset tokens are secure, short-lived, session-bound, and single-use:**  
  Reset tokens are generated with cryptographically secure randomness (`crypto.getRandomValues`), are 32 bytes, are stored only as SHA-256 hashes, expire after 15 minutes, are bound to the initiating session, and are permanently marked used before password hashing.

- **PASS — CSRF protections are present on sensitive requests:**  
  Every POST endpoint requires a matching session-backed CSRF token in both the `X-CSRF-Token` request header and CSRF cookie. Tokens are generated per session. Cookies use `Secure`, `HttpOnly`, `SameSite=Strict`, and scoped paths.

- **PASS — Sensitive actions enforce server-side authorization:**  
  Password confirmation requires a verified reset token for the current session. MFA verification requires `mfaPending`. Privacy acceptance requires `session.authenticated`. No route accepts an account ID, user ID, course folder, or other IDOR-style identifier.

- **PASS — XSS and unsafe DOM injection protections are implemented:**  
  Browser-generated messages use `textContent`; user input is not interpolated into HTML. The application does not use `innerHTML`, `eval`, dynamic script loading, or external script resources. CSP uses per-response nonces for the trusted embedded style and script blocks.

- **PASS — Secure browser/server headers are configured:**  
  Responses include HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`, and `Cache-Control: no-store`.

- **PASS — Password policy and secure password storage are implemented:**  
  Passwords must be 12–128 characters and include uppercase, lowercase, a number, and a symbol, with no spaces. Password hashes use Bun bcrypt with cost 10. Plaintext passwords are not persisted.

- **PASS — Login and verification throttling/lockout are implemented:**  
  Reset requests are rate-limited by a server-side contact digest. Reset verification failures are throttled. Login failures and MFA failures trigger a ten-minute lock after five failures.

- **PASS — MFA is implemented for the simulated flow:**  
  Both password-reset completion and normal login require a second MFA verification step before authentication is set. The deterministic MFA code is appropriate for the explicitly simulated training environment and is browser-logged as required.

- **PASS — No open redirects, SSRF, or external network calls:**  
  The application does not accept destination URLs, does not redirect to arbitrary locations, and does not perform outbound network requests. Client requests are same-origin API calls only.

- **PASS — Safe-authentication guidance is present:**  
  The UI warns users not to share passwords or security codes and explicitly states that staff will not request them by email or phone.

- **PASS — Internal SPA navigation functions:**  
  Navigation buttons switch among recovery, verification, login, MFA, password, and privacy views. Hash-based verification-link handling is implemented and validation is server-side.

- **PASS — Production-safe error handling is present:**  
  Server exceptions return a generic error response without stack traces, diagnostics, or sensitive details.

- **PASS — Code validation:**  
  The TypeScript structure, top-level `await`, Bun APIs (`Bun.serve`, `Bun.password`, `Bun.CryptoHasher`), request handling, and browser JavaScript are internally consistent and contain no apparent syntax or runtime-logic errors under the stated Bun environment.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks are required.

## DECISION

PASS