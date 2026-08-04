## SUMMARY

The artifact is a strong single-file Bun HTTPS SPA with a functional simulated recovery, reset, sign-in, MFA, and privacy-acceptance flow. It includes CSRF protections, secure cookies, CSP/HSTS headers, token hashing/expiry/single-use handling, password hashing, XSS-safe DOM rendering, and throttling. However, it does not fully meet the inclusivity requirement to let users pause and return without losing progress: an in-progress approved-channel secret is lost on reload/navigation, while the server remains at the channel-confirmation stage.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server, HTML, CSS, and vanilla browser JavaScript**
  - All application code, the Bun server, inline HTML/CSS/client JavaScript, and TLS setup are contained in `app.ts`.
  - No framework, bundler, compiler, or external network assets are used.

- **PASS — HTTPS and certificate use**
  - The server requires `certs/cert.pem` and `certs/key.pem`, exits if they are absent, and starts Bun with TLS configured.
  - Secure cookies and HSTS are configured.

- **PASS — Password-recovery flow is implemented**
  - The UI supports account-email entry, approved-channel confirmation, recovery code/link delivery, manual recovery-code submission, password update, sign-in, MFA, and privacy-statement acceptance.
  - Internal recovery links work through `/recovery/verify?token=...`.
  - Manual token entry is available through “Enter a code manually.”

- **PASS — Simulated delivery is shown in browser console**
  - The client calls `console.log()` through `addLog()` for the approved-channel secret, reset token/link, and MFA code.
  - Reset tokens are also returned to the UI client as required for testing.

- **PASS — Reset tokens are cryptographically generated, hashed, single-use, and short-lived**
  - Reset tokens use `randomBytes`.
  - Only hashes are retained server-side.
  - Tokens expire after 15 minutes and are invalidated after password change.

- **PASS — CSRF protection and state-changing request controls**
  - POST endpoints require a session, same-origin `Origin` header, and a session-specific CSRF token.
  - Cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — XSS defenses**
  - User-controlled values are inserted using DOM APIs and text nodes rather than HTML interpolation.
  - Client-side dynamic content does not use `innerHTML`.
  - CSP uses a per-page nonce and disallows default sources.

- **PASS — Password policy and password hashing**
  - Passwords require at least 12 characters with uppercase, lowercase, number, and symbol, and prohibit spaces.
  - Updated passwords are hashed with Bun Argon2id before storage.

- **PASS — Authentication protections and throttling**
  - Login failures are throttled after five failures.
  - Recovery-channel and token-verification attempts are throttled.
  - MFA is implemented and also limits failed attempts.

- **PASS — Privacy and anti-phishing guidance**
  - The UI includes help and safety advice, including warnings not to share passwords or recovery codes.
  - Privacy acceptance is protected by the authenticated session state.

- **FAIL — Users can pause and return without losing progress**
  - While the recovery session stage is retained server-side, the approved-channel authorization secret is only retained in the in-memory client `logs` array.
  - If the user refreshes the page, navigates away, closes/reopens the tab, or otherwise reloads while at the `channel` stage, `logs` is reset to `[]`.
  - The app restores the user to the channel-confirmation screen but no longer provides the authorization secret required to continue.
  - There is no “resend authorization secret” endpoint or UI action to recover from this state without restarting.

- **FAIL — Timeout messaging is inaccurate and can create confusion**
  - The Help page states: “There are no timeouts in the browser.”
  - In reality, recovery tokens expire after 15 minutes, and sessions expire after 24 hours.
  - The 15-minute security expiry is appropriate, but the UI must explain it clearly rather than claiming there are no timeouts.

## FAILING_ITEMS

- The approved-channel authorization secret is lost after page reload/navigation because it is only held in the transient `logs` JavaScript array.
- A restored server session at stage `channel` cannot be completed after the secret is lost; the user must abandon/restart recovery, contrary to the pause-and-return requirement.
- There is no secure recovery/resend action for a user who returns to the approved-channel confirmation step after losing the simulated delivery message.
- Help text incorrectly says there are “no timeouts,” despite the 15-minute reset-token expiration and 24-hour session expiration.

## NEW_TASKS

1. Add a recovery-delivery resend mechanism for the approved-channel step, with a CSRF-protected endpoint that safely issues a replacement authorization secret, invalidates the prior secret, preserves generic/non-enumerating responses, and writes the simulated delivery to the browser console.
2. Add a visible “Send the authorization secret again” action on the approved-channel screen so a restored `channel`-stage session can continue without restarting the entire flow.
3. Update saved-progress behavior so returning users are clearly restored to their valid server-backed step and can obtain any required simulated delivery value again.
4. Replace the Help-page statement that there are “no timeouts in the browser” with accurate low-stress wording explaining that progress is saved while valid, recovery codes expire after a stated period for safety, and users can request/restart recovery if a code expires.

## DECISION

FAIL