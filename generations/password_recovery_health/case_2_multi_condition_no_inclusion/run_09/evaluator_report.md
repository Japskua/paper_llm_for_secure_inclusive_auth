## SUMMARY

The artifact is a valid single-file Bun HTTPS password-recovery SPA. It implements the recovery, token verification, password reset, MFA, privacy acceptance, and appointment confirmation flow with server-side session authorization, CSRF validation, secure token handling, rate limits, CSP/security headers, and browser-console simulated delivery values. No blocking syntax, runtime, routing, or security-flow faults were identified.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application / zero build tooling:** All server logic, HTML, CSS, and client-side vanilla JavaScript are contained in `app.ts`. It uses Bun directly, with no framework, bundler, compiler step, external assets, or external network calls.

- **PASS — HTTPS and certificate use:** The Bun HTTPS listener reads `certs/cert.pem` and `certs/key.pem`. A separate HTTP listener redirects only approved localhost hosts to the configured HTTPS origin.

- **PASS — Secure headers and transport policy:** HTTPS responses include HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, permissions policy, cross-origin policies, and no-store caching headers.

- **PASS — CSRF protection:** Each server-side session receives a cryptographically random CSRF token. All state-changing API requests require both the exact configured HTTPS `Origin` and a timing-safe CSRF-token comparison.

- **PASS — Session protections:** Sessions use cryptographically random IDs in `__Host-` cookies with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and expiration. Session data is held server-side.

- **PASS — Access control / IDOR prevention:** Sensitive endpoints derive authorization exclusively from the current server-side session. No client-controlled account, patient, course, or object identifiers are accepted by protected routes.

- **PASS — XSS and injection prevention:** The server returns a static HTML shell. Client-controlled or server-returned dynamic display values are inserted with `textContent`, not `innerHTML`. The token query parameter is assigned only to an input’s `.value`. CSP restricts scripts to the generated nonce.

- **PASS — No private identifiers exposed through the portal:** The account’s internal ID and email hash remain server-side. The browser state endpoint does not disclose usernames, patient records, email addresses, account IDs, password hashes, or tokens.

- **PASS — Password-reset token security:** Reset tokens are generated using `randomBytes`, only token hashes are stored server-side, tokens are session-bound and account-bound, expire after 15 minutes, and are single-use. A verified reset creates a separate short-lived, one-use reset grant.

- **PASS — Manual and link-based verification:** A generated local verification link routes to `/reset?token=...`, and the verification page also supports manual token entry. The link and manual-entry path both invoke the same secure server-side validation.

- **PASS — Browser-console simulated delivery:** The reset token and MFA test code are returned for this explicitly simulated environment and logged using browser-side `console.log` through the `log()` function. The browser UI additionally shows a simulation log without using unsafe HTML insertion.

- **PASS — Enumeration-resistant recovery response:** Recovery requests return the same response structure and generic message for matching and non-matching emails. Non-matching addresses receive random opaque decoy tokens that cannot be verified.

- **PASS — Brute-force mitigation:** Reset verification is locked after five failures, reset requests are rate-limited to three per ten-minute session window, and MFA verification is limited to five attempts.

- **PASS — Password policy and password hashing:** New passwords require at least 12 characters and uppercase, lowercase, numeric, and symbol characters. Passwords are stored using Bun bcrypt hashing with cost 12; plaintext passwords are not retained.

- **PASS — MFA implementation:** After a successful password reset, the flow requires a one-time MFA code before authentication is established. MFA is server-side session-bound and attempt-limited.

- **PASS — Authenticated privacy and appointment workflow:** Privacy acceptance requires authentication. Appointment confirmation requires both authentication and privacy acceptance. The client routes users through recovery, MFA, privacy acceptance, and appointment confirmation based on server-provided state.

- **PASS — Safe redirect and host handling:** Redirect destinations are constructed from the configured HTTPS origin rather than the untrusted `Host` header. Both listeners reject unexpected hosts.

- **PASS — UX and semantic structure:** The UI uses semantic sections, headings, labels, forms, accessible live-region behavior, clear password guidance, clear safety guidance, and actionable feedback for errors and success states.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No corrective tasks required.

## DECISION

PASS