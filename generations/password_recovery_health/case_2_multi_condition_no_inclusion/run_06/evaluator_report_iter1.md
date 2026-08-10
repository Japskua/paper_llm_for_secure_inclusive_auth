## SUMMARY

The artifact is a single-file Bun HTTPS SPA with strong baseline controls: per-session CSRF tokens, HttpOnly/Secure/SameSite cookies, CSP nonces, opaque reset tokens, session-owned recovery records, bcrypt password hashing, and browser-console mock delivery logs. However, it has a broken email-validation regex, client-side-only workflow/confirmation routing that can falsely show completion without server authorization, and rate limiting that is easily bypassed by creating new sessions/recovery records. These defects prevent acceptance.

## FUNCTIONAL_CHECK

- **PASS — Single-file delivery and zero-compilation operation:** The server, HTML, CSS, and vanilla browser JavaScript are contained in `app.ts`. It uses Bun directly, has no framework, build step, bundler, or external assets.
- **PASS — Bun HTTPS server uses provided certificates:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and startup fails rather than silently serving insecure HTTP when they are absent.
- **PASS — No external network calls:** Browser requests are same-origin API requests only; no remote scripts, styles, images, APIs, redirects, or outgoing URL fetching is implemented.
- **PASS — Recovery flow UI exists and is usable:** The app provides recovery-email, manual token verification, MFA verification, password reset, privacy acceptance, and confirmation views.
- **PASS — Verification-link and manual-token paths work:** The simulated token is included in a fragment link (`#verify?token=...`) and is also prefilled into a manually submittable token field.
- **PASS — Browser mock logging is implemented:** Simulated recovery-token and MFA delivery are logged with `console.log` in browser-side JavaScript, and the token is returned to and displayed in the UI as required for testing.
- **PASS — Sensitive state-changing API calls use CSRF validation:** Every `POST /api/...` request requires a valid session, an `X-CSRF-Token` header, and matching `csrf` body value.
- **PASS — Session cookie protections are present:** The `sid` cookie is random and is set with `HttpOnly`, `Secure`, `SameSite=Strict`, path restriction, and a finite lifetime.
- **PASS — Recovery records prevent IDOR between sessions:** `ownedRecovery` checks that the recovery record belongs to the requesting session before token, MFA, password, or privacy actions can proceed.
- **PASS — Account enumeration is mostly avoided:** The recovery API always creates a generic recovery response and does not expose usernames, account existence, patient data, or other private identifiers.
- **FAIL — Email-format validation is faulty:** The regex uses double backslashes in a regex literal:  
  `^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$`  
  This does not mean whitespace/dot matching as intended. It rejects normal addresses such as `person@example.com` and can accept malformed values containing a literal backslash. Additionally, because the result is returned as `acceptedFormat`, response content varies based on input validity despite the UI claiming the same generic response.
- **PASS — XSS defenses are generally sound:** Dynamic client-side values are added through `textContent` and DOM APIs rather than interpolated into HTML. User-controlled email, token, MFA, and password values are not reflected into HTML.
- **PASS — CSP and standard browser hardening headers are configured:** Responses include CSP with per-page nonces, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store caching.
- **PASS — Reset tokens are random, hashed, short-lived, and single-use:** Tokens use `crypto.getRandomValues`, only SHA-256 hashes are stored, expiration is 15 minutes, and successful verification clears the token hash and marks the token used.
- **PASS — Sensitive errors do not disclose stack traces:** The top-level handler catches unexpected exceptions and returns a generic response.
- **PASS — Passwords are not stored or logged in plaintext:** Password values are not rendered or console-logged, and successful passwords are hashed with Bun bcrypt at cost 12.
- **FAIL — Password policy does not account for bcrypt’s 72-byte password limit:** The UI/server allow passwords up to 128 JavaScript characters, but bcrypt only processes the first 72 bytes. Distinct long passwords can therefore hash equivalently after truncation. The policy should cap UTF-8 byte length at 72 or use an explicit secure pre-hashing strategy.
- **PASS — Password complexity policy is otherwise enforced server-side:** The server requires at least 12 characters with upper case, lower case, digit, and symbol, and does not rely only on the client UI.
- **PARTIAL/FAIL — Brute-force/recovery throttling is not robust:** Token, MFA, password, and recovery request counters exist, but they are scoped to a session/recovery object. An attacker can create fresh sessions or new recovery records to reset the counters. The recovery-request limit in particular is trivially bypassed by obtaining another session cookie.
- **PASS — MFA exists within the simulated flow:** MFA is required after token verification before password reset. The deterministic code is appropriate for the explicitly simulated/demo delivery requirement.
- **PASS — Phishing/social-engineering guidance is shown:** Each view warns users not to share passwords, reset tokens, or MFA codes and recommends using the trusted hospital address directly.
- **PASS — No SSRF/open redirect implementation is present:** The app does not accept or request arbitrary outgoing URLs, and navigation targets are a fixed whitelist of hash views.
- **FAIL — Client workflow routes are not server-authorized:** A user can directly navigate to `#mfa`, `#reset`, `#privacy`, or `#confirmation` before completing earlier steps. The backend correctly rejects unauthorized state-changing API calls, but the UI still renders protected-stage forms and, more importantly, displays “Recovery complete” and claims that privacy acceptance was recorded without verifying server state. This is misleading and means confirmation-screen access is not controlled.
- **PASS — Internal links themselves resolve correctly:** The hash links use supported, whitelisted view names and do not lead to missing pages.

## FAILING_ITEMS

- The recovery email regex is incorrectly escaped. It does not validate ordinary email input as intended and may recognize malformed backslash-containing input instead.
- `/api/recovery` returns `acceptedFormat`, making its otherwise generic response vary according to user input validation. This is unnecessary and conflicts with the stated generic-response behavior.
- The SPA renders MFA, password reset, privacy, and completion screens based solely on `location.hash`. It does not verify recovery progression with the server before displaying them. In particular, `#confirmation` falsely asserts a completed reset/privacy acceptance even when no actions occurred.
- Attempt throttling is scoped only to an easily replaceable session/recovery state. New sessions and new recovery requests bypass the limits, so the throttle is not an effective protection against automated requests/guessing.
- The password policy permits values beyond bcrypt’s effective 72-byte limit, creating silent password truncation ambiguity.

## NEW_TASKS

1. Correct the email regex to use proper regex-literal escapes, for example `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`, and remove `acceptedFormat` from the recovery API response so the response remains fully generic.
2. Add a server-authoritative recovery-status endpoint that returns only the current session’s permitted progression state; use it to redirect/block `#mfa`, `#reset`, `#privacy`, and `#confirmation` unless the required server-side milestones have been completed.
3. Add a completion-state check before rendering the confirmation view so it cannot claim password reset and privacy acceptance unless `passwordHash` and `privacyAccepted` are present for the owned recovery.
4. Implement rate limiting that cannot be reset merely by creating a new session or recovery record, such as a bounded IP-based limiter combined with session-based limits; apply it to recovery initiation and verification attempts.
5. Enforce bcrypt-compatible password length using UTF-8 byte length, rejecting passwords over 72 bytes, or explicitly pre-hash passwords using a documented secure strategy before bcrypt.

## DECISION

**FAIL**