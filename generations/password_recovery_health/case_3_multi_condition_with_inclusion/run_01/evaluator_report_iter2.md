## SUMMARY

The artifact is a valid single-file Bun/TypeScript SPA with a generally clear, accessible recovery flow, TLS configuration, CSP nonce usage, CSRF checks, Argon2id hashing, and simulated browser-console delivery. However, it does not fully meet the security and link-functionality requirements: account existence can be enumerated through the reset response, rate limiting is bypassable or incomplete, reset tokens are not strictly single-use at verification, and recovery links fail when opened in a fresh session.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and client application:** The server, HTML, CSS, and browser JavaScript are all contained in `app.ts`. No framework, bundler, external assets, or external network calls are used.

- **PASS — Bun TLS configuration:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required.

- **PASS — HTTPS/security headers:** The application configures HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, no-store caching, Secure cookies, HttpOnly cookies, and `SameSite=Strict`.

- **PASS — CSRF protection on sensitive requests:** POST API routes require a session-specific CSRF token and reject invalid or missing values.

- **PASS — Password security policy and hashing:** Passwords require 12+ characters with upper/lowercase, digit, and symbol. Passwords are stored using `Bun.password.hash(..., { algorithm: "argon2id" })`, not plaintext.

- **PASS — MFA simulation works:** After a valid password login, the MFA code is generated and displayed through browser-side `console.log` and the Logs panel. MFA is required before privacy acceptance.

- **PASS — Reset code can be manually entered:** The recovery code is displayed in browser logs and can be manually entered into the recovery-code field.

- **FAIL — Recovery verification links function correctly:** The generated link is `/?token=...`, but opening it in a new browser/session does not show the Verify step or populate the code. `initialize()` only honors a URL token when `data.step === "verify"`, which is false for a new session (`start`).

- **FAIL — Account identifiers are not protected from enumeration:** Although the text message is generic, `/api/request-reset` returns a `token` only when an account exists. An attacker can inspect the JSON response or UI behavior to determine whether an email is registered.

- **FAIL — Automated guessing and reset abuse are not adequately blocked:** Login and reset verification throttling is stored only in the current session. Attackers can obtain a new session/cookie and continue attempts. `/api/request-reset` has no throttling at all and can generate unlimited tokens for a known account.

- **FAIL — Reset-token single-use behavior is incomplete:** A reset token remains valid after successful `/api/verify-reset`; it is only invalidated after `/api/reset-password`. The same token can be submitted to verify repeatedly before the password is changed, contrary to a strict single-use verification-token requirement.

- **PASS — XSS handling:** User-derived content is written with `textContent`, not `innerHTML`; token links are generated with `encodeURIComponent`; no user input is reflected into HTML. The nonce-based CSP restricts script execution.

- **PASS — Sensitive authorization checks:** Password reset requires a verified reset token held in the session, and privacy acceptance requires authenticated MFA completion. No client-provided account ID is accepted by sensitive endpoints.

- **PASS — ADHD/inclusivity design:** The UI is structured into distinct steps, provides visible progress, clear status messages, no UI timeout/countdown, pause reassurance, a prominent help option, and low visual density.

- **FAIL — Progress display is incomplete during MFA:** The progress indicator has only Start, Verify, New password, and Sign in. When the user reaches MFA, the UI still highlights “Sign in” rather than showing a distinct MFA/identity-confirmation step, reducing orientation in a multi-step flow.

- **PASS — Safe-authentication guidance and SSRF/open-redirect avoidance:** The help text warns users not to share passwords or recovery codes. The app makes no outbound requests and generated recovery URLs are same-origin.

## FAILING_ITEMS

- Reset-account enumeration is possible because valid-account responses contain a `token`, while unknown-account responses do not.
- Reset-request creation is unthrottled, permitting repeated token generation and possible delivery/resource abuse.
- Login and reset-code throttles are session-only and can be bypassed by starting a new session.
- `ResetRecord.failures` is never incremented, so the intended token-level lockout is nonfunctional.
- A successfully verified reset token remains reusable until password submission instead of being consumed at verification.
- Recovery links do not correctly resume the Verify step when opened with a fresh session.
- MFA is not represented as a separate visible progress step.

## NEW_TASKS

1. Make reset-request responses and UI behavior indistinguishable for known and unknown email addresses, including returning a safe simulated delivery result for both cases without exposing whether a real account exists.

2. Add server-side throttling for `/api/request-reset`, scoped to an appropriate abuse-control key such as normalized email plus client IP/session, with a bounded retry window.

3. Replace session-only login and reset-verification throttling with server-side rate limits that cannot be bypassed merely by creating a new session; remove or correct the unused `ResetRecord.failures` logic.

4. Consume a reset token immediately after successful verification and create a separate, short-lived, session-bound password-reset grant for `/api/reset-password`.

5. Update client initialization so a valid `?token=` recovery URL always opens the Verify step and pre-fills the manual token field, including in a newly created session.

6. Add a distinct MFA step to the progress indicator and mark it active while the MFA section is displayed.

## DECISION

FAIL