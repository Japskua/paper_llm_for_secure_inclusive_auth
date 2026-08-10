## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a well-structured password recovery flow, server-side sessions, CSRF protection, rate limiting, bcrypt password hashing, reset-token expiry/single-use handling, MFA simulation, and browser-console mock delivery logging. Most functional and security requirements are met. However, the promised pause/resume behavior fails during the password-creation step because the required reset grant exists only in JavaScript memory and cannot be restored after a reload or resume. There is also a malformed CSS declaration and incomplete requirement-mapping comments. Therefore, the artifact cannot be accepted as fully compliant.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun server and SPA implementation**
  - The complete server, HTML, CSS, and browser-side vanilla JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly with no framework, bundler, compiler, external assets, or external network requests.

- **PASS — TLS configuration and secure transport**
  - The Bun server is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server checks for `https:` URLs and sets HSTS through `Strict-Transport-Security`.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **PASS — Recovery flow is functionally implemented**
  - The SPA supports recovery request, simulated delivery, manual recovery-code entry, recovery-link prefill, code verification, password replacement, MFA confirmation, privacy-condition acceptance, and completion.
  - The simulated recovery-link flow works in the same browser session: `/recovery-link?token=...` pre-populates the manual verification field without automatically consuming the token.

- **PASS — Browser-console simulated delivery**
  - Recovery codes and MFA codes are returned only for the demonstration flow and are logged through the browser-side `console.log`.
  - The reset token is also visibly made available through the simulated-delivery UI, satisfying the testing requirement.

- **PASS — ADHD/inclusivity-oriented UI design, except resume reliability**
  - The interface has visible numbered progress, concise step-specific language, clear feedback, help content, anti-phishing reminders, no countdown UI, and pause/resume controls.
  - The visual hierarchy is relatively low-distraction and uses semantic structure.
  - However, the pause/resume promise is not reliably fulfilled at every stage; see the failing item below.

- **FAIL — Pause and return without losing recovery progress**
  - At the password step, `resetGrant` is only held in the client variable `resetGrant`.
  - If the user reloads, closes/reopens the page, or uses “Resume recovery” while on this step, `/api/status` reports `recoveryStep: "password"` but does not return a usable reset grant.
  - The UI renders the password form, but submission sends an empty `grant`, causing `/api/password` to reject it with “Please verify a recovery code before creating a password.”
  - This contradicts the UI promise that resume “will restore your current secure server step” and violates the requirement to let the user pause and return without losing progress.

- **PASS — CSRF protection**
  - Sensitive POST routes require a per-session CSRF token via `X-CSRF-Token`.
  - The CSRF token is generated server-side per session and is not placed in the URL.
  - Cookie settings and CSP further reduce cross-origin request risks.

- **PASS — Access control and reset authorization**
  - Recovery tokens are random, hashed before storage, expire after 15 minutes, and are marked single-use before issuance of a reset grant.
  - Reset grants are random, short-lived, single-use, and bound to both the session ID and account key.
  - Password updates require the verified session-bound reset grant.
  - Privacy acceptance requires authentication established through MFA.

- **PASS — Injection/XSS defenses**
  - Client-side user-controlled strings are inserted with `textContent`, not `innerHTML`.
  - The application does not interpolate user input into server-rendered HTML.
  - CSP uses a per-response nonce and restricts scripts, styles, framing, object embedding, and outbound connections.
  - Input validation is present for identifiers, tokens, passwords, and MFA codes.

- **PASS — Authentication protections**
  - Passwords are hashed with bcrypt using `Bun.password.hash`.
  - Passwords are never logged.
  - MFA is implemented as a mock second factor.
  - Login, recovery, verification, password update, MFA, and privacy actions have server-side rate limiting.
  - Password policy requires 12+ characters with uppercase, lowercase, number, and symbol.

- **PASS — Privacy and phishing guidance**
  - The interface repeatedly warns users not to share passwords or one-time codes.
  - It advises users to verify the HTTPS hospital address and not trust password requests by email.
  - No actual patient records, usernames, course folders, or non-demo account data are exposed.

- **FAIL — Clear comments mapping implementation to all requirement sections**
  - There are some useful comments, especially around TLS, CSRF, token consumption, and reset grants.
  - However, comments do not clearly and comprehensively map the client-side inclusivity flow, XSS handling, CSP/security headers, rate limiting, MFA, and anti-phishing behavior back to the stated requirement sections.
  - This only partially meets the explicit deliverable requirement for clear requirement-mapping comments.

- **FAIL — CSS validity**
  - The CSS rule for `code` contains an invalid declaration:
    ```css
    overflow-wrap:anywhere)
    ```
  - The trailing `)` makes that declaration malformed. While browsers will generally ignore only that declaration, the artifact contains a concrete syntax defect.

## FAILING_ITEMS

- The password-reset grant is lost from client memory after page reload or resume at the password-creation stage, while the server still reports that the user is at the password step. This leaves the user unable to complete the step without restarting recovery.
- The UI makes an inaccurate recovery-resume promise: it says the current secure server step will be restored, but the password step cannot be completed after restoration because no usable grant is available.
- The CSS declaration `overflow-wrap:anywhere)` has a syntax error.
- Requirement-mapping comments are incomplete, particularly for the browser-side inclusivity behavior and several security controls.

## NEW_TASKS

1. Add a secure, CSRF-protected password-step resume mechanism that can issue a new short-lived, single-use reset grant only to the existing verified server session when `currentRecoveryStep(session) === "password"`. Invalidate any previous grant before issuing the replacement grant.

2. Update the client resume/bootstrap logic so that, when the server-confirmed recovery step is `password`, it obtains the replacement reset grant before rendering or submitting the password form. Ensure the user can complete password creation after a reload or pause/resume action without re-entering the recovery code.

3. Update the pause/resume text so it accurately describes what is preserved and any security-limited conditions, such as reset-code and reset-grant expiration.

4. Correct the malformed CSS declaration by changing:
   ```css
   overflow-wrap:anywhere)
   ```
   to:
   ```css
   overflow-wrap:anywhere
   ```

5. Add concise comments in `app.ts` that explicitly map the client and server sections to the relevant requirements: ADHD/inclusivity flow, XSS-safe rendering, CSP/security headers, CSRF, rate limiting, reset-token lifecycle, MFA, and anti-phishing guidance.

## DECISION

**FAIL**