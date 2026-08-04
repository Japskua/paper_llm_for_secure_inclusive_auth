## SUMMARY

The artifact is a well-structured single-file Bun SPA with a functional simulated reset, manual token entry, session-bound CSRF, CSP nonce protection, bcrypt password hashing, password policy enforcement, and browser-side mock logging. However, it does not fully meet the security and flow requirements: it can run insecurely over HTTP when certificates are absent, its reset-delivery behavior leaks account eligibility and permits reset initiation based only on a known mock email, throttling is bypassable by creating new sessions, and it claims privacy conditions are accepted without an explicit consent step. Therefore, it cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` implementation with Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The entire application is contained in `app.ts`, uses Bun directly, has no framework, build step, bundler, external asset, or external network call.

- **HTTPS/TLS enforcement and use of provided certificates: FAIL**
  - When certificates exist, the app correctly starts a TLS server and an HTTP-to-HTTPS redirect listener.
  - However, when certificates are absent, it starts the sensitive application over plain HTTP:
    ```ts
    Bun.serve({ port, fetch: safeFetch });
    ```
  - This directly violates the requirement that HTTPS must be enforced. It also conflicts with the `Secure` session cookie configuration.

- **Security headers, HSTS, CSP, anti-clickjacking, and cache controls: PASS**
  - The server configures CSP with per-response nonces, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, no-referrer policy, permissions policy, COOP/CORP, and no-store caching headers.
  - The inline style and script are nonce-authorized by the CSP.

- **CSRF protection on sensitive requests: PASS**
  - State-changing API routes require a session-bound CSRF token.
  - The token is generated randomly per session and compared with `timingSafeEqual`.
  - The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `/`, and uses the `__Host-` prefix correctly.

- **XSS/injection handling and safe output rendering: PASS**
  - Browser-side rendering uses `textContent`, `replaceChildren`, and DOM APIs rather than interpolating user input via `innerHTML`.
  - User-controlled query-string token content is validated before use and is never rendered.
  - API messages are server-controlled constants.
  - CSP meaningfully restricts script execution.

- **Reset-token security and manual/link verification: PASS**
  - Reset tokens are generated with cryptographically secure randomness, expire after 10 minutes, are session-bound, and are marked single-use.
  - Both the recovery-link route (`/reset?token=...`) and manual code submission are implemented.
  - The browser logs the simulated delivery object, including the token and link, via `console.log`, as required for the academic mock.

- **Password policy and password storage: PASS**
  - Passwords require 12–128 characters with uppercase, lowercase, numeric, and symbol characters.
  - Passwords are hashed with bcrypt through `Bun.password.hash`.
  - The application does not persist plaintext passwords.

- **MFA and reset completion flow: PASS**
  - A deterministic simulated MFA code is provided after password change and must be verified before the completion screen.
  - MFA attempts are limited per session.

- **Brute-force/rate-limit protection: FAIL**
  - Reset-token and MFA attempts are throttled only within a session.
  - An attacker can bypass the limits simply by starting a new session, receiving a new session cookie, or repeatedly using fresh browser contexts.
  - The reset-request limit is also per session, so it can be bypassed the same way.
  - This does not adequately meet the requirement that automated guessing attempts be throttled or blocked.

- **Protection of private identifiers and prevention of account enumeration: FAIL**
  - `/api/request-reset` returns `delivery` only when the supplied email equals `MOCK_ACCOUNT_EMAIL`.
  - Although the displayed message is generic, a caller can distinguish whether an email is the mock account by checking whether the response includes `delivery` and whether a token is logged.
  - The source also contains a patient-associated mock email:
    ```ts
    const MOCK_ACCOUNT_EMAIL = "helena.patient@example.test";
    ```
  - This creates an account-eligibility oracle and exposes a private-style identifier in the artifact.

- **Unauthorized password-reset prevention: FAIL**
  - Any caller who knows the hardcoded mock email can request a valid reset token and immediately receive that token in their own browser response/log.
  - Session binding prevents another session from using the specific token, but it does not prevent an unauthorized visitor from obtaining a new valid token for the mock account and resetting its password.
  - The simulated delivery mechanism needs a mock account-ownership proof that does not rely only on knowledge of an identifier.

- **Privacy-conditions acceptance UX: FAIL**
  - The completion view states that updated privacy conditions “have been accepted,” but the app never displays the conditions, requests consent, or persists an acceptance action.
  - There is no explicit user confirmation or server-side `privacyAccepted` state.

- **Safe navigation / no open redirects / anti-phishing guidance: PASS**
  - Navigation is restricted to fixed internal paths.
  - No user-provided destination URL is followed.
  - The UI provides clear anti-phishing guidance not to share passwords, reset links, or verification codes.

- **Error handling and production-safe responses: PASS**
  - The server catches unexpected errors and returns a generic response without stack traces or debug details.
  - Invalid requests return generic errors rather than leaking internal implementation information.

## FAILING_ITEMS

- The server falls back to serving the entire recovery application over plain HTTP if TLS certificate files are unavailable. This violates mandatory HTTPS enforcement.

- Reset delivery is conditional on the supplied email and exposes a `delivery` object only for the matching account. This enables account enumeration through API responses/browser logs.

- The hardcoded patient-style email identifier is embedded in the server source and is sufficient to trigger a reset flow.

- A visitor who knows the mock email can obtain a reset token in their own session and reset the shared mock password without demonstrating account ownership. This does not adequately prevent unauthorized password resets.

- Reset-token, MFA, and reset-request rate limits are scoped only to a session. Attackers can evade them by creating fresh sessions.

- The UI claims privacy conditions have been accepted, but there is no privacy statement, checkbox/confirmation control, CSRF-protected consent endpoint, or persisted consent state.

## NEW_TASKS

1. Remove the plaintext HTTP application fallback. If `certs/cert.pem` or `certs/key.pem` is unavailable, fail startup with a generic local configuration error rather than serving recovery endpoints over HTTP. Keep the separate fixed-origin HTTP-to-HTTPS redirect listener only when TLS is active.

2. Redesign `/api/request-reset` so its observable response shape is identical regardless of supplied email and does not conditionally expose a `delivery` property based on account existence.

3. Replace the hardcoded patient-style email reset trigger with a non-identifying academic test mechanism that requires a simulated account-ownership verification step before issuing a reset token, while still returning/logging the deterministic mock token in the browser after that proof succeeds.

4. Add shared server-side throttling that cannot be bypassed by starting a new session. Apply it to reset requests, reset-token verification failures, and MFA verification failures using an appropriate server-visible scope such as client address plus action and/or a generic global demo limit.

5. Add an explicit privacy-conditions step after MFA: display the conditions, require an affirmative checkbox/action, submit it through a CSRF-protected endpoint, persist a session `privacyAccepted` state, and show the final appointment-booking confirmation only after consent succeeds.

## DECISION

**FAIL**