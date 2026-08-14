## SUMMARY

The artifact is a single-file Bun SPA with a strong overall structure: TLS setup, secure headers, owner-bound sessions, CSRF checks, encrypted TOTP seed storage, hashed recovery codes, rate limiting, mobile-oriented UI, copy options, QR rendering, and browser-console-only simulated values. However, it does not fully meet the authentication and inclusive UX requirements because identity codes are re-issued with the same value, sign-in cannot be retried after one failed attempt without refreshing, TOTP entry has a short implicit practical deadline, and form labels are not programmatically associated with inputs.

## FUNCTIONAL_CHECK

- **Single-file Bun server, HTML, CSS, and browser JavaScript with no build tools or external assets: PASS**
  - All application code is in `app.ts`.
  - The server uses `Bun.serve`, serves inline HTML/CSS/JS, and does not use frameworks, bundlers, external assets, or network calls.
  - TLS certificates are loaded from the required `certs/cert.pem` and `certs/key.pem` paths.

- **Mobile responsive, dyslexia-aware UI and reduced reading load: FAIL**
  - The layout, spacing, plain-language text, icons, large controls, responsive breakpoint, copy buttons, hide/reveal controls, and lack of animations are good.
  - However, authenticator verification practically expires after approximately 90 seconds because only `[now - 1, now, now + 1]` TOTP time steps are accepted. This conflicts with the requirement to avoid time pressure and allow generous time to enter codes.
  - The screen says “Take your time,” but a user who takes longer can receive an error and must restart setup.

- **Semantic and accessible HTML: FAIL**
  - Forms use visible `<label>` elements, but they are not associated with their corresponding controls via `for`/`id`, nor do they wrap the inputs.
  - Screen-reader and accessibility tooling may therefore not correctly expose field labels.

- **Clear flow, internal navigation, recovery, retry, hide/reveal, and copy options: FAIL**
  - Internal hash routes are implemented and protected appropriately.
  - QR, provisioning URI copying, manual setup-key copying, recovery-code copying, hiding/revealing, recovery-code testing, and re-request controls are present.
  - However, a failed sign-in cannot be retried normally. `/api/signin` deletes the login CSRF token on every attempt, while the client retains `loginCsrf`; after an invalid-password response, a subsequent submission sends the consumed token and fails with “Please refresh the sign-in page and try again.” This violates the requirement that users can retry without penalty.

- **Simulated OTP/recovery behavior and working verification: FAIL**
  - Identity codes, authenticator OTPs, and recovery codes are returned to the browser client and logged through browser `console.log`, as required for testing.
  - Authenticator OTPs are validated with TOTP and recovery codes are single-use after successful verification.
  - Identity-code re-requests are not distinct: `identityCode(session.id)` always produces the same six-digit code for the same session. Re-requesting replaces the old challenge but produces the same usable code, so a previously disclosed/unconsumed identity code remains valid for the new challenge. This does not meet the requirement for verification codes to be single-use.

- **Broken access control protections: PASS**
  - MFA endpoints use `owned()` and derive the account exclusively from the authenticated session.
  - The API does not accept account IDs/user IDs in request bodies due to the `object()` validation guard.
  - Manipulated or guessed user IDs cannot be used for IDOR.
  - State-changing authenticated requests enforce an `X-CSRF-Token`.

- **Sign-in CSRF and secure session handling: PASS**
  - Sign-in uses a short-lived double-submit CSRF mechanism with a SameSite cookie and header comparison.
  - The authenticated session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions are regenerated at sign-in, expire by idle and absolute timeout, and are invalidated on logout.

- **Security misconfiguration protections: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store` are set.
  - CORS permits only configured localhost TLS origins.
  - Server errors are generic and do not disclose stack traces.
  - Sensitive values are not written to server logs, URLs, error responses, or the visible activity-log panel.

- **Cryptographic protections: PASS**
  - TOTP seeds are generated with `crypto.getRandomValues` and stored encrypted using AES-GCM.
  - Recovery codes are generated with cryptographic randomness and stored as salted hashes rather than plaintext.
  - TLS is enabled directly in Bun and HSTS is sent.
  - Secrets and tokens are not stored in `localStorage`, `sessionStorage`, or non-HttpOnly session cookies.

- **Input validation, XSS prevention, and redirect safety: PASS**
  - Server-side validation exists for email, password, OTP, and recovery-code formats.
  - API input is constrained to plain objects and rejects identifier/redirect fields.
  - No user-controlled values are interpolated into server HTML; client insertion uses `textContent` for sensitive dynamic data.
  - Routing is allow-listed through a fixed hash-route set, with no arbitrary redirect parameter.

- **Rate limiting, lockouts, and generic authentication errors: PARTIAL / FAIL**
  - Failed identity, authenticator, and recovery-code attempts are rate limited and locked after five failures.
  - Generic sign-in failure wording avoids account enumeration.
  - However, the identity-code implementation does not produce a fresh code for each request, which prevents full compliance with the single-use verification-code criterion.

- **Code validity / runtime viability: PASS**
  - No clear TypeScript/Bun syntax error is present.
  - The Bun APIs, TLS configuration, response creation, Web Crypto calls, and browser JavaScript structure are plausible for Bun 1.3.0 and a modern mobile browser.
  - The custom QR renderer has an internal decoder check before rendering.

## FAILING_ITEMS

- **Identity-code re-requests generate the same code for the entire session.**
  - `identityCode(session.id)` is deterministic and only depends on the session ID.
  - Requesting another identity code creates a new challenge hash but hashes the same six-digit value.
  - A previously obtained identity code can therefore validate the latest challenge, contrary to the single-use verification-code requirement.

- **A failed sign-in forces a page refresh instead of allowing a normal retry.**
  - The server deletes `loginTokens` on every `/api/signin` attempt.
  - The client does not clear and re-bootstrap `loginCsrf` after a failed sign-in.
  - The next sign-in attempt uses an already-consumed token and fails CSRF validation.

- **Authenticator-code entry is not sufficiently generous for the stated dyslexia-inclusive UX.**
  - The server accepts only the prior, current, and next 30-second TOTP periods.
  - The displayed simulated OTP can become unusable within roughly 90 seconds even though the UI says there is no time pressure.
  - The user must regenerate the provisioning secret rather than simply continuing after taking more time.

- **Input labels are not semantically connected to controls.**
  - Examples include the email, password, identity-code, authenticator-code, and recovery-code fields.
  - The markup uses standalone `<label>` tags without `for` attributes and inputs without matching `id` attributes.

## NEW_TASKS

1. Replace session-derived identity-code generation with a fresh cryptographically secure code for every `/api/identity/request`; store only its salted hash in the challenge, invalidate the prior challenge, and retain the browser-console simulation behavior.

2. Update the sign-in client flow so every failed `/api/signin` response clears the consumed `loginCsrf` value and obtains a fresh `/api/csrf-bootstrap` token before the user’s next attempt.

3. Expand authenticator verification to accept a bounded but materially more generous past TOTP window (while retaining single-use time-step tracking and lockouts), and adjust the UI wording so the actual acceptance window is truthful.

4. Add unique `id` attributes to every form input and matching `for` attributes to each corresponding `<label>` (or wrap each input within its label).

## DECISION

**FAIL**