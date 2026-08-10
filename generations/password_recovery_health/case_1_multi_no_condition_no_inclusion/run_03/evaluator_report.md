## SUMMARY

The artifact meets the password recovery, verification, MFA, password update, and privacy-acceptance flow requirements in a single `app.ts` file. It uses Bun’s native server/runtime capabilities, serves HTTPS when the required certificates are present, uses session-bound CSRF protection, avoids unsafe DOM rendering, and simulates delivery values through the browser console and UI as required.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application and zero-build compliance:** The HTML, CSS, browser JavaScript, server logic, security controls, and TLS setup are all contained in `app.ts`. No framework, bundler, compiler step, package dependency, or external asset is used.

- **PASS — HTTPS/TLS usage:** The server uses `certs/cert.pem` and `certs/key.pem` when available. If TLS files are missing, the application does not expose recovery functionality and returns a generic `503` response.

- **PASS — Security headers and HTTPS hardening:** Responses include HSTS, CSP with a per-response nonce, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, restrictive `Referrer-Policy`, `Permissions-Policy`, and no-cache headers.

- **PASS — Session security:** Session IDs and CSRF tokens are cryptographically random. The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, path-restricted, and uses the `__Host-` prefix correctly.

- **PASS — CSRF prevention:** All state-changing API endpoints require a valid session, matching HTTPS same-origin `Origin`, and a session-specific CSRF token validated using constant-time comparison.

- **PASS — Reset-token handling:** Recovery tokens are random 256-bit values, stored only as SHA-256 digests, expire after ten minutes, and are consumed before MFA issuance. Replayed or expired tokens are rejected.

- **PASS — Manual code and verification-link flow:** The recovery code can be manually submitted. The generated fragment link pre-populates the code field without sending it to the server in a URL request, and the user still must submit it for verification.

- **PASS — MFA and brute-force controls:** A deterministic MFA mock code is issued only after successful reset-code verification. MFA attempts are limited and temporarily locked after repeated failures.

- **PASS — Password policy and password storage:** The server enforces a strong password policy and hashes accepted passwords with Bun bcrypt. Plaintext passwords are not stored, returned, or logged.

- **PASS — Access-control flow:** Password update requires a verified and consumed reset token plus successful MFA. Privacy acceptance requires completion of the password-reset flow. No client-controlled account, patient, course, or resource identifiers are accepted by protected routes.

- **PASS — XSS and injection protections:** User-supplied account input is not rendered or retained. Dynamic browser output uses `textContent`, `createTextNode`, and controlled attribute assignment rather than unsafe `innerHTML`. The CSP blocks unapproved script execution.

- **PASS — No information disclosure:** Recovery responses are generic and do not disclose whether an account exists. Errors are generic where appropriate, and the server catch block does not reveal stack traces or diagnostics.

- **PASS — No external calls, SSRF, or open redirects:** The client makes only same-origin API calls. No server-side outbound requests, external URLs, redirects, or user-controlled redirect destinations exist.

- **PASS — Safe-authentication guidance and UX:** The UI contains explicit warnings not to share passwords or codes, instructs users to confirm the secure hospital address, provides clear stage-specific messages, and supports keyboard/focus navigation.

- **PASS — Browser-console mock delivery requirement:** The recovery token and deterministic MFA code are logged from browser-side JavaScript and are also presented in the UI for test purposes.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No changes required.

## DECISION

**PASS**