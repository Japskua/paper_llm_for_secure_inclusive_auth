## SUMMARY

The artifact is a single-file Bun HTTPS application with a mostly complete password recovery, password replacement, login, MFA, privacy acceptance, and appointment confirmation flow. It implements many important controls correctly, including TLS configuration, secure cookies, CSP nonces, CSRF checks, rate limiting, Argon2id password hashing, MFA checks, and browser-console mock delivery values. However, the advertised recovery-link flow does not work across sessions/browsers because reset state is stored only in the original session, and the UX does not provide a consistently visible progress indicator or an actionable help route. Therefore, the artifact does not fully meet the requirements.

## FUNCTIONAL_CHECK

- **Single `app.ts` containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The supplied artifact is one TypeScript file and serves its HTML/CSS/client JS directly through Bun without frameworks, bundlers, external assets, or external network calls.

- **Bun server uses provided TLS certificate paths: PASS**
  - `Bun.serve` is configured with `tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }`.

- **HTTPS/security response headers are configured: PASS**
  - The application returns HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, and no-store cache headers.
  - The CSP uses a server-generated nonce for the controlled inline style and script.

- **CSRF protection on sensitive requests: PASS**
  - Sensitive POST routes require a valid per-session CSRF token and an exact same-origin `Origin` header.
  - The session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, and uses a valid `__Host-` prefix configuration.

- **Sensitive operations enforce authorization: PASS**
  - Privacy acceptance and appointment confirmation require a session with completed MFA.
  - Appointment confirmation also requires prior privacy acceptance.
  - No user/account identifiers are exposed through object identifiers or URL parameters for protected actions.

- **Password reset tokens are random, expiring, and single-use: PASS, with recovery-link limitation**
  - Tokens are generated cryptographically, expire after 15 minutes, and are marked used after password replacement.
  - However, the token is bound only to the originating session, causing the recovery-link workflow itself to fail in a new browser/session.

- **Manual reset-token verification works: PASS in the originating browser session**
  - The browser logs the mock reset token and exposes a form for manually submitting it.
  - The token comparison uses timing-safe equality and failed attempts are throttled.

- **Recovery verification link works correctly: FAIL**
  - The API returns a `deliveryPath` such as `/?recovery-test=<token>`, and the UI supports this URL.
  - However, opening the link in a different browser, browser profile, device, or a cleared/expired session creates a new session with no associated `reset` object.
  - `/api/recovery/instruction` only checks `c.session.reset`, rather than looking up and validating the submitted token globally. The result is that a legitimate recovery link fails unless it is opened with the original session cookie.
  - This does not meet the requirement that internal verification links function correctly.

- **Password policy and secure password storage: PASS**
  - New passwords require at least 12 characters with uppercase, lowercase, number, and symbol.
  - Password hashes use `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Passwords are not stored in plaintext in account state.

- **Login protection and MFA: PASS**
  - Login failures are throttled/locked after repeated failures.
  - MFA requires a six-digit mock code plus a separate possession value.
  - Protected actions reject expired MFA sessions.

- **Mock delivery values are shown in the browser console: PASS**
  - Reset token, recovery identity value, MFA code, and possession value are logged with browser-side `console.log`.
  - The reset token is also returned to the client UI/API response for test purposes.

- **Input handling and XSS protections: PASS**
  - Client rendering uses `textContent`, not unsafe `innerHTML`.
  - User-controlled values are not interpolated into server HTML.
  - Inputs are validated server-side and CSP blocks arbitrary scripts.

- **Request-body size limit is robustly enforced: FAIL**
  - `body()` trusts the `Content-Length` header:
    ```ts
    const n = Number(request.headers.get("content-length") || "0");
    if (!Number.isFinite(n) || n > 8192) throw Error("bad body");
    const value = await request.json();
    ```
  - A request can omit `Content-Length` or provide an inaccurate value while sending a large body. The server then parses the full request body without an actual enforced byte limit.
  - This is a validation/resource-consumption weakness and should be corrected.

- **Clear, visible progress throughout the multi-step flow: FAIL**
  - Individual sections include some step numbers, but only the current card is visible and there is no persistent progress indicator showing where the user is in the full process.
  - The identity stage is also not numbered consistently between “2” and “3.”
  - This falls short of the ADHD-focused requirement for visible, continuous orientation and progress reminders.

- **Pause/resume support: PASS, within session lifetime**
  - Server-side session state persists for eight hours and the UI restores stages through `/api/state`.
  - The browser preserves the account reference and reset token in `sessionStorage`.
  - Reset tokens appropriately remain short-lived for security.

- **Help is easy to access at every stage: FAIL**
  - The page has a static “Need help or a reminder?” card, but it does not provide an actionable help method, such as a hospital support number, accessible help panel, or clear route back to assistance.
  - The card may also be below the fold and is not persistently available during every stage.

## FAILING_ITEMS

- The recovery verification URL (`/?recovery-test=<token>`) does not work when opened outside the originating session because reset-token state is only stored in `session.reset`.
- Manual token verification is likewise tied to the originating session rather than securely resolving a valid reset token from server-side reset-token state.
- Request-body size validation relies on the untrusted/optional `Content-Length` header and does not enforce an actual parsed-body byte limit.
- The multi-step interface lacks a persistent, consistently numbered progress indicator.
- The “Need help” area is informational only and does not provide an actionable, easily accessible support option throughout the process.

## NEW_TASKS

1. Replace session-only reset-token storage with a server-side reset-token record store keyed by a cryptographic hash of the reset token, containing the account key, expiry, used state, recovery identity value/hash, and attempt counters.

2. Update the recovery-link handler and manual token submission endpoint so a valid reset token can securely initialize or attach recovery state to the current session, including when opened from a new browser session.

3. Ensure the reset token remains single-use by atomically marking it consumed when the password is successfully replaced, and reject expired, invalid, or already-used token records.

4. Enforce request-body limits from actual received bytes rather than trusting `Content-Length`; reject oversized JSON bodies before parsing them.

5. Add a persistent progress component visible on every step, with consistent steps such as: “1 Request recovery → 2 Confirm token → 3 Verify identity → 4 New password → 5 Sign in and safety checks → 6 Privacy → 7 Appointment.”

6. Add an actionable, consistently accessible help option, such as a “Contact hospital account support” button/panel with a mock support number and clear reminder that staff will never request passwords or recovery codes.

## DECISION

FAIL