## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functional password recovery, manual-token verification, password policy, simulated MFA, privacy acceptance flow, CSRF protection, restrictive headers, and browser-console mock delivery logging. However, it does not fully meet the security requirements because server-side sessions never expire, the MFA code is reusable and never expires despite being presented as one-time, and the client JavaScript is implemented as an inline script despite the explicit requirement to disallow inline scripts.

## FUNCTIONAL_CHECK

- **Single `app.ts` containing Bun server, HTML, CSS, and browser JavaScript — PASS**
  - The complete server and SPA template are contained in one file. It uses Bun directly and does not rely on frameworks, build tools, compilation steps, or external assets.

- **Bun HTTPS server using supplied certificates — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, binds to `localhost`, and all application content is served through this TLS server.

- **Password recovery flow works end-to-end — PASS**
  - A user can request recovery, receive a simulated random recovery token, verify it manually or through the generated `/reset?stage=verify&token=...` link, set a password, complete MFA, accept privacy conditions, and view a confirmation screen.

- **Recovery token is random, short-lived, hashed, session-bound, and single-use — PASS**
  - Recovery tokens are generated with `crypto.getRandomValues`, stored only as SHA-256 hashes, expire after ten minutes, are consumed upon verification, and create a separate five-minute reset authorization.

- **Manual recovery-code submission and recovery link support — PASS**
  - The application pre-populates the token when the reset link is opened and also provides an “I have a recovery code” path for manual entry.

- **Simulated delivery is logged in the browser console and visible in the UI — PASS**
  - Reset tokens, reset links, and simulated MFA codes are logged through browser-side `console.log`, as required. Dynamic log output uses `textContent`.

- **Strong password policy and secure password storage — PASS**
  - Passwords require 12–128 non-whitespace characters with upper-case, lower-case, number, and symbol requirements. Passwords are hashed with Bun bcrypt before storage.

- **CSRF protections on state-changing routes — PASS**
  - All POST API endpoints require the session-bound `X-CSRF-Token`, use constant-time comparison, and use a `Secure`, `HttpOnly`, `SameSite=Strict` session cookie.

- **Sensitive route access control — FAIL**
  - Server-side session records have no expiration timestamp or validation. The cookie has `Max-Age=1800`, but an expired cookie can still be manually replayed because the matching session remains indefinitely in the `sessions` map. A stolen or retained `sid` therefore remains valid beyond the intended 30-minute session duration.

- **MFA / one-time security-code protection — FAIL**
  - `MFA_CODE` is a permanent global value, has no issuance or expiry time, and is not consumed after successful verification. The `/api/mfa` endpoint will continue accepting `482915` indefinitely for any session with `passwordSet === true`. This conflicts with the UI’s “one-time simulated security code” language and weakens the MFA/security-code requirement.

- **Brute-force throttling — PASS**
  - Reset-token and MFA verification attempts are throttled after five failures for 60 seconds.

- **XSS and output-escaping protections — FAIL**
  - User-controlled values are generally allowlisted and never inserted through HTML interpolation, which is good. However, the page includes a direct inline `<script nonce="...">` block. The requirements explicitly state that inline scripts must not be allowed. A CSP nonce authorizes this inline script but does not make it non-inline.

- **Security headers and anti-clickjacking configuration — PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, Referrer Policy, Permissions Policy, cache-control headers, COOP, and CORP are configured.

- **No external network calls or open redirects — PASS**
  - All browser requests are same-origin API requests. The recovery link is generated internally, and user input is not used as a navigation or outgoing URL target.

## FAILING_ITEMS

- **Server-side sessions do not expire.**
  - `Session` has no expiry field, `getSession()` does not enforce age, and old session entries are never deleted. Cookie expiration alone is not adequate because a replayed `sid` remains accepted by the server.

- **The MFA/security code is neither time-limited nor single-use.**
  - `MFA_CODE` is a static application-wide value.
  - The session does not record when the code was issued.
  - Successful MFA validation does not mark the code consumed.
  - Repeated calls to `/api/mfa` with the same code continue to succeed after password recovery.

- **The browser application uses an inline script.**
  - The HTML includes `<script nonce="${nonce}">`.
  - This conflicts with the requirement that no inline scripts be allowed, even though the nonce is correctly implemented.

## NEW_TASKS

1. **Add server-enforced session expiration.**
   - Add an `expiresAt` field to `Session`.
   - Set it when creating a session, matching the 30-minute cookie lifetime.
   - Update `getSession()` to reject and delete expired sessions.
   - Periodically remove expired session entries or remove them whenever they are encountered.

2. **Make simulated MFA codes session-bound, short-lived, and single-use.**
   - Add MFA issuance, expiry, and consumed-state fields to `Session`.
   - Issue the deterministic mock MFA code only after successful password creation.
   - Require an unexpired, unconsumed issued MFA challenge in `/api/mfa`.
   - Mark the MFA challenge consumed after a successful verification.
   - Clear or invalidate the MFA challenge after expiry, reissued recovery, or password-reset restart.

3. **Remove the inline browser script while preserving the single-file architecture.**
   - Store the client JavaScript in an `app.ts` string constant.
   - Serve it from an internal same-origin route such as `/client.js`.
   - Replace the inline script block with `<script src="/client.js" defer></script>`.
   - Update CSP from nonce-based inline script authorization to a restrictive same-origin script policy such as `script-src 'self'`.
   - Keep the CSS and all server/client code within `app.ts`.

## DECISION

**FAIL**