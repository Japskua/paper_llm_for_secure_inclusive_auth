## SUMMARY

The artifact is a valid single-file Bun/TypeScript implementation with a polished, low-distraction recovery UI, HTTPS/TLS setup, CSP nonces, CSRF protections, secure cookies, token expiry/single use, password hashing, simulated browser-visible delivery values, and functional manual/link-based token verification. However, it does not fully meet the authentication throttling and pause/resume requirements. In particular, rate limiting is only session-scoped and can be bypassed by creating new sessions, and a user who pauses immediately after requesting a reset code cannot reliably retrieve the simulated code/activity record after a reload.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla browser JavaScript: PASS**
  - The provided artifact is one TypeScript file and directly serves the complete application. No framework, bundler, compiler step, or external asset is required.

- **Bun HTTPS server uses the prescribed mkcert certificate paths: PASS**
  - `readFileSync("certs/cert.pem")` and `readFileSync("certs/key.pem")` are used in `Bun.serve({ tls: { cert, key } })`.
  - An HTTP listener redirects to a fixed HTTPS `localhost` URL.

- **HTTPS and secure response headers are configured: PASS**
  - HTTPS is served on port 3443, HTTP redirects with status `308`, and HTTPS responses include HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers.

- **CSRF protections apply to sensitive state-changing requests: PASS**
  - A high-entropy per-session CSRF token is generated and required through `X-CSRF-Token` for all state-changing recovery, MFA, password-change, and login endpoints.
  - The session cookie uses `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Access control and reset-token ownership are enforced: PASS**
  - Reset tokens are stored server-side in the owning session and verification requires the current secure-cookie session’s matching token.
  - Password changes require a valid, unexpired, unused verified reset token plus completed MFA.
  - There are no user IDs, usernames, patient records, or object IDs exposed through routes.

- **Reset tokens are random, short-lived, and single-use: PASS**
  - Tokens use `randomBytes(32).toString("base64url")`, expire after 15 minutes, and are marked `used` after a successful password change.
  - Reuse is prevented by `resetIsValid()` and the `used` flag.

- **Reset delivery and MFA are simulated and visible in the browser console/UI: PASS**
  - The server returns deterministic testing values to the browser.
  - The client calls `audit(...)`, which writes these values to `console.log` in the browser and safely displays them in the activity log.
  - The recovery token can be submitted manually or through the simulated recovery link.

- **XSS/injection protections are adequate for this implementation: PASS**
  - User-provided contact input is never rendered back to the page or logged.
  - Dynamic client rendering uses `textContent`, not `innerHTML`.
  - CSP uses a per-response nonce and restricts scripts, connections, framing, forms, and object sources.
  - Route responses are JSON generated via `JSON.stringify`, rather than interpolation of untrusted values.

- **Password policy and password storage are secure: PASS**
  - Passwords require at least 12 characters, uppercase, lowercase, numeric, and symbol characters, with no whitespace.
  - Passwords are hashed with Bun’s bcrypt implementation and are not logged or retained as plaintext.

- **MFA is present in the reset process: PASS**
  - A recovery-token verification step is followed by a separate security-code confirmation step before password change.
  - The fixed MFA value is reasonable for the explicitly required deterministic mock environment.

- **Brute-force/login-attempt mitigation: FAIL**
  - Attempt limits are only stored per session (`session.attempts`).
  - An automated attacker can repeatedly create a new session via `/api/session`, obtain a new CSRF token, and receive five new login, reset-token, or MFA guesses per session indefinitely.
  - This does not meet the requirement that automated guessing attempts be throttled or blocked after repeated failures.

- **No open redirects / outgoing URL control: PASS**
  - The only browser navigation is a fixed same-origin `/recovery?reset=...` path.
  - The HTTP redirect always targets `https://localhost:3443` and does not use a caller-controlled hostname.

- **Safe-authentication/social-engineering guidance is provided: PASS**
  - The help panel clearly says staff will never ask for passwords or security codes and instructs users to verify the HTTPS localhost address and use a known hospital phone number if concerned.

- **ADHD-oriented, step-by-step, low-stress UX: PASS**
  - The UI includes visible five-step progress, clear plain-language headings, calm guidance, activity feedback, no visual clutter, no countdown UI, and readily available help.

- **Pause and return without losing progress: FAIL**
  - Only the numeric current step is stored in `localStorage`.
  - Immediately after a successful recovery-code request, the reset token is stored only in the JavaScript variable `lastToken` and displayed only in the current activity log/browser console.
  - After a refresh or return visit, the user is returned to step 2 but the activity log is empty, `lastToken` is empty, and no safe UI action lets them retrieve/re-display the simulated recovery code or request another one.
  - This can leave the user unable to continue despite the UI claiming their place is saved.

- **Internal navigation and recovery-link behavior: PASS**
  - The “Open simulated recovery link” button navigates to the fixed recovery route, automatically verifies the supplied token, and removes the token from the browser URL afterward.
  - Manual code entry remains available.

- **Production error/debug exposure: PASS**
  - Request handling catches unexpected errors and returns generic errors without stack traces or debug output to clients.

## FAILING_ITEMS

- **Session-only throttling is bypassable.**
  - Login, reset-token verification, and MFA verification limits are tied solely to the current session. An attacker can start new sessions to avoid the lockout indefinitely.

- **Pause/resume is incomplete after reset-code issuance.**
  - The persisted step can indicate step 2 even though the user no longer has access to the simulated delivery token after a reload.
  - The activity log is not persisted, and the UI does not provide a “send/request another recovery code” action on step 2.

## NEW_TASKS

1. **Add a non-session-only rate limit for authentication-sensitive endpoints.**
   - Apply throttling to `/api/login`, `/api/reset/verify`, and `/api/mfa/verify` using a server-side limiter keyed by a trustworthy client identifier where available (for example, Bun request IP handling), with a conservative global fallback if no trustworthy address is available.
   - Keep the existing session-level limits as an additional defense.
   - Return a generic `429` response while the lockout is active, without exposing account or token information.

2. **Make recovery-code progress resumable after a browser reload.**
   - Add a safe step-2 UI control such as “Request another recovery code” that creates a replacement token for the already authenticated browser session and shows the new deterministic simulated value in the browser console/activity log.
   - Ensure requesting a replacement invalidates the prior reset token.
   - Update the pause guidance so it accurately explains that users can return and request a new practice code if the prior code is no longer available.

## DECISION

**FAIL**