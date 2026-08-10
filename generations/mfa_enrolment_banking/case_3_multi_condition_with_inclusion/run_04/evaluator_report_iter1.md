## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally clear mobile MFA flow, server-side session ownership checks, CSRF checks, security headers, encrypted authenticator-secret storage, hashed recovery codes, and browser-side mock logging. However, it does not currently work reliably in a browser because its Origin allow-list rejects its own `https://localhost:3000` POST requests. It also lacks the required QR-code option, does not time-bound or rate-limit authenticator verification attempts, and overwrites valid sessions whenever `/` is loaded.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and inline SPA implementation**
  - The supplied artifact is one `app.ts` file containing the Bun server, HTML, CSS, and browser JavaScript. It uses no framework, bundler, compiler step, or external assets.

- **PASS — HTTPS/TLS server configuration**
  - `Bun.serve` is configured with `tls: { cert, key }` using `certs/cert.pem` and `certs/key.pem`, as required.

- **FAIL — Core sign-in and MFA state-changing actions work in the browser**
  - The server rejects any request with an `Origin` other than exactly `https://localhost`.
  - The app is served on port `3000`, so browser fetch requests commonly send `Origin: https://localhost:3000`. This does not equal `https://localhost`, causing sign-in and every other POST action to receive `403 Not allowed.`

- **PASS — Responsive, mobile-oriented, accessible presentation**
  - The UI uses a narrow `main` layout, legible font sizing, spacing, visible focus styles, plain-language instructions, short examples, form labels, autocomplete attributes, and predictable steps.

- **PASS — Dyslexia-conscious UX measures**
  - The interface avoids dense prose and timers, uses generous spacing and readable typography, supports retry/resend operations, provides examples, and offers copy/download actions for long recovery values.

- **FAIL — QR-code option is offered for authenticator provisioning**
  - The requirements explicitly call for QR-code options. The app offers a provisioning URI and manual secret only; it renders no QR code.

- **PASS — Manual authenticator setup option and clipboard support**
  - The provisioning URI and manual secret are displayed, can be copied, and the user can submit the resulting six-digit authenticator code manually.

- **PASS — Recovery-code creation, display, copy, download, regeneration, and single-use verification**
  - Recovery codes are generated, displayed safely via `textContent`, can be copied/downloaded, are hashed before storage, regenerate as a replacement set, and are removed after successful verification.

- **PASS — Server-side ownership enforcement / IDOR prevention**
  - Protected MFA routes derive the account identity solely from the HttpOnly session. No MFA route accepts a user ID from the client, and `ownerSession` ensures the signed-in account matches the expected account.

- **PASS — CSRF protection on state-changing MFA operations**
  - State-changing API routes require the request’s `x-csrf-token` to match the token in the active server-side session.

- **PASS — Secure session cookie attributes and authentication-time session rotation**
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`. The session ID is rotated after successful password authentication. Idle and absolute expiry checks are implemented, and logout removes the session.

- **FAIL — Session continuity and correct session-cookie handling**
  - `page()` always calls `newSession()` and always emits a new `Set-Cookie` header, including when the requester already has a valid authenticated MFA session.
  - Refreshing `/` therefore replaces the authenticated cookie with a new anonymous session and loses the user’s enrolment progress/settings state.

- **PASS — Security headers and generic server errors**
  - CSP with per-page nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, restrictive referrer/permissions policies, and generic catch-all error responses are present.

- **FAIL — CORS is correctly restricted to the actual trusted application origin**
  - Although CORS is intended to be restricted, the configured allowed origin is incorrect for this server’s port and breaks legitimate requests. The emitted `Access-Control-Allow-Origin: https://localhost` likewise does not match `https://localhost:3000`.

- **PASS — Sensitive values are not server-logged or placed in URLs/browser storage**
  - No server `console.log` is used for secrets, OTPs, codes, or session IDs. Sensitive mock values are not put into URLs, `localStorage`, `sessionStorage`, or non-HttpOnly cookies. Browser `console.log` use is explicitly required for the mock/testing flow.

- **PASS — Cryptographic generation and at-rest protection**
  - Random values use `crypto.getRandomValues`; the authenticator secret is AES-GCM encrypted for stored state; recovery codes are stored as SHA-256 hashes with a server-side pepper.

- **FAIL — Authenticator OTP verification is time-bound and rate-limited**
  - `/api/authenticator/start` creates `owner.pendingOtp`, but no expiry timestamp is stored or checked for it.
  - `/api/authenticator/verify` has no failed-attempt counter, rate limit, or lockout. An attacker with a valid session can make unlimited guesses until the six-digit code is found.

- **PASS — Identity and recovery verification have expiry/single-use/lockout controls**
  - Identity codes have a ten-minute expiry, become used after successful verification, and lock after five failures. Recovery codes are single-use and lock after repeated failures.

- **PASS — Input handling and output encoding**
  - Code formats and lengths are checked server-side. User-controlled values are not directly interpolated into HTML; dynamic displayed values are set with `textContent`. There is no database usage or redirect parameter accepting external destinations.

## FAILING_ITEMS

- Legitimate same-origin POST requests from `https://localhost:3000` are rejected because the server only accepts `Origin: https://localhost`.
- The response CORS header also incorrectly declares `Access-Control-Allow-Origin: https://localhost` rather than the actual application origin.
- No QR code is provided during authenticator provisioning despite the QR-code requirement.
- Authenticator mock OTPs have no expiry and can be guessed with unlimited verification attempts.
- Loading or refreshing `/` always overwrites the current session cookie with a new anonymous session, ending an otherwise valid authenticated session.

## NEW_TASKS

1. Update origin validation and CORS response handling to allow the actual trusted app origin, including port (for example, `https://localhost:3000`), and ensure same-origin browser POST requests are not rejected.
2. Stop setting a new anonymous session cookie unconditionally from `page()`. Only create/set a session when no valid session exists, such as through `/api/session`, while preserving an existing valid session on page refresh.
3. Add a QR-code provisioning option generated entirely locally/inline, alongside the existing provisioning URI, manual secret, and copy controls.
4. Add authenticator OTP expiry state and enforce it in `/api/authenticator/verify`.
5. Add failed-attempt counting plus a rate limit/temporary lockout for `/api/authenticator/verify`, with a specific user-facing error message and a retry/new-setup path.

## DECISION

FAIL