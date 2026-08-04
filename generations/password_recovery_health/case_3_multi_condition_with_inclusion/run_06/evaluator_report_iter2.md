## SUMMARY

The artifact is a strong single-file Bun implementation with HTTPS, session cookies, CSRF checks, random reset tokens, MFA simulation, password hashing, throttling, CSP/security headers, and a clear recovery UI. The core reset flow works in the originating browser session, including simulated link and manual token entry. However, it does not fully meet the stated security and UX requirements: it uses an inline executable script despite the explicit prohibition on inline scripts, and persisted client-side step state can show users an unauthorized or expired later step without reconciling it against server-side recovery state.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and no compilation/build tooling**
  - All server logic, HTML, CSS, and client JavaScript are in `app.ts`.
  - It uses `Bun.serve` directly and has no framework, bundler, package dependency, external asset, or network request.

- **PASS — HTTPS enforcement and prescribed TLS certificate paths**
  - The HTTPS server loads `certs/cert.pem` and `certs/key.pem`.
  - The HTTP listener only returns a fixed `308` redirect to `https://localhost:3443`.
  - HTTPS responses include HSTS and other protective headers.

- **PASS — CSRF/session protections for sensitive actions**
  - Sensitive POST endpoints use `protectedRequest`.
  - Sessions have cryptographically random IDs and per-session CSRF tokens.
  - Cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and path-scoped.
  - Sensitive API operations validate the `X-CSRF-Token` header.

- **PASS — Password reset token requirements**
  - Tokens are generated with `randomBytes`, are 32 random bytes encoded as base64url, and have a 15-minute expiry.
  - Replacement token requests invalidate the previous token.
  - Tokens are marked used once the password is successfully changed.
  - The UI supports both a simulated recovery link and manual recovery-code entry.

- **PASS — Authentication protections**
  - The application uses bcrypt through `Bun.password.hash(... algorithm: "bcrypt")`.
  - Passwords are not logged or rendered after submission.
  - Strong-password checks are enforced client-side and server-side.
  - MFA is implemented with a deterministic mock code for testing.
  - Login, reset-token verification, and MFA verification have session and cross-session throttling.

- **PASS — XSS-safe dynamic rendering**
  - Client-generated status and activity-log content is assigned with `textContent`, not `innerHTML`.
  - User-provided contact data is not rendered or persisted.
  - The application does not interpolate user input into server HTML.

- **FAIL — No inline scripts requirement**
  - The HTML response includes executable inline JavaScript in a `<script nonce="${nonce}">...</script>` block.
  - A CSP nonce permits this script, but the requirement explicitly states: “No inline or untrusted scripts are allowed.”
  - The client JavaScript should be served from a same-origin JavaScript route implemented within the same `app.ts` file, with CSP changed to use `script-src 'self'` and without a nonce-authorized inline script.

- **PASS — Security headers and error handling**
  - CSP, HSTS, clickjacking protection, MIME sniffing protection, referrer policy, permissions policy, and no-store caching are configured.
  - Generic error messages are returned and stack traces are not exposed.
  - No directory-listing or debug endpoint is present.

- **PASS — No external redirects / outgoing requests**
  - The simulated recovery link uses a fixed same-origin `/recovery` route.
  - The HTTP redirect destination is fixed to `https://localhost:3443`.
  - No fetches or navigation are made to external domains.

- **FAIL — Pause/resume state is not reliably reconciled with server-side authorization state**
  - The UI restores `recovery-step` directly from `localStorage`, but `/api/session` only reports whether a recoverable code exists.
  - A user with stale local storage can be shown step 3, 4, or 5 even if the server session has expired, the reset token was replaced, MFA was never completed, cookies were cleared, or a different session is active.
  - For example, a user can see “Choose a new password” at step 4 but receive a generic `403` upon submission because `mfaVerified` is false.
  - This conflicts with the ADHD-oriented requirements for clear feedback, predictable progress, and returning without confusion.

- **PASS — Low-stress, accessible recovery UI overall**
  - The UI has numbered visible progress, concise step-specific instructions, status regions with `aria-live`, clear labels, keyboard focus styling, no countdown, and persistent help.
  - It provides safe-authentication reminders and a clear “request another code” recovery path.

- **PASS — Browser-console mock visibility**
  - The reset token and MFA code are returned to the UI and emitted through the browser-side `audit()` function, which calls browser `console.log`.
  - The activity log uses safe text rendering.

## FAILING_ITEMS

- The application contains an inline executable `<script>` block. A CSP nonce makes it CSP-authorized, but it does not comply with the explicit requirement that inline scripts are not allowed.

- Client progress restoration relies on `localStorage` without sufficient server-state reconciliation. This can display an invalid recovery step after expiration, cookie/session loss, token replacement, or incomplete verification.

- When restored progress is invalid, the UI generally produces a generic API failure rather than clearly returning the user to the first valid recovery step and explaining what happened.

## NEW_TASKS

1. Move the browser JavaScript from the inline `<script>` block into a same-origin JavaScript response route, such as `GET /app.js`, while keeping the route implementation and JavaScript source inside `app.ts`.

2. Update the page HTML to load the client code with `<script src="/app.js" defer></script>` and update CSP to remove nonce-based inline-script authorization and enforce `script-src 'self'`.

3. Extend `/api/session` to return a server-derived recovery state, such as `request`, `code`, `mfa`, `password`, or `finished`, based on the current session’s reset, verification, MFA, and completion state.

4. On browser startup, reconcile `localStorage` progress with the server-provided recovery state; reset the UI to the earliest valid step when local progress is stale or unauthorized.

5. Add clear user-facing recovery-state messages for expired, replaced, or unavailable reset progress, including an explicit action to return to step 1 or request a fresh code.

## DECISION

FAIL