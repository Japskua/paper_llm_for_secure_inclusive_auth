## SUMMARY

The artifact is a well-structured single-file Bun HTTPS application with a functional staged recovery flow, CSRF protection, CSP/security headers, password hashing, throttling, and an accessible low-distraction UI. However, it does not fully satisfy the required mock-delivery and verification workflow: the MFA code is never shown or logged to the user, and the generated reset token/link is not returned to the UI or browser console. There is also a significant authorization flaw because password storage is global and recovery requests are not bound to an account, allowing any valid-looking identifier to initiate a reset affecting the same shared password hash.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and vanilla client JavaScript: PASS**
  - The full server and client application are contained in one file.
  - No frameworks, build tools, bundlers, or external assets are used.

- **Bun HTTPS server uses the supplied certificate locations: PASS**
  - The server reads `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with TLS and serves HTTPS on port 3000.

- **Password recovery flow is rendered as a guided SPA: PASS**
  - The UI provides request, verification, MFA, password reset, sign-in, and privacy-confirmation stages.
  - Rendering occurs client-side without unexpected navigation.

- **Manual recovery-code verification works: PASS**
  - `/api/recovery-request` returns `testCode`.
  - The client logs the received manual recovery code to the browser console and visible Logs panel.
  - `/api/verify` can verify the entered code.

- **Recovery link/token verification is testable and functional: FAIL**
  - The server creates a random `session.resetToken` and supports `/api/verify` with a `token`.
  - However, the reset token is never returned in the recovery-request response, never shown in the UI, never logged in the browser console, and no verification URL is generated.
  - Therefore, the token/link path cannot be exercised by a tester through the intended UI/mock delivery flow.

- **MFA verification can be completed through the UI: FAIL**
  - `/api/verify` returns `testMfaCode: "246810"`.
  - The client ignores `result.testMfaCode` and never logs or displays it.
  - The MFA screen falsely states that the code is available in the visible Logs panel and browser console, but it is not.
  - A normal user/tester cannot complete MFA without inspecting source code or network responses.

- **Password policy and password hashing are enforced: PASS**
  - Passwords must be 12–128 characters and contain upper-case, lower-case, numeric, and special characters.
  - Passwords are hashed using `Bun.password.hash(..., { algorithm: "bcrypt" })`.
  - Password values are not placed in logs or rendered output.

- **Reset token security properties are implemented server-side: PARTIAL / FAIL**
  - The token is randomly generated, session-scoped, and expires after ten minutes.
  - The reset path becomes unusable after the password is changed.
  - However, the test-facing delivery requirement is not met because the token is inaccessible to the UI/console.
  - Additionally, the token is not explicitly marked used at successful verification; stage checks prevent reuse in practice, but explicit consumption at verification would be clearer and safer.

- **CSRF protections are present for sensitive requests: PASS**
  - Each session has a unique CSRF token.
  - All POST API routes require the token through `X-CSRF-Token` or request body validation.
  - Session cookies use `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **XSS/input handling protections are present: PASS**
  - Client-generated content uses DOM APIs and `textContent`, rather than unsafe HTML interpolation.
  - The page uses a nonce-based CSP.
  - Input validation is present on the server for identifiers, codes, and passwords.
  - No user-controlled values are interpolated into HTML.

- **Security headers and HTTPS configuration are present: PASS**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-store cache headers are configured.
  - The application rejects proxy-marked HTTP requests.

- **Brute-force throttling is implemented: PASS**
  - Recovery, verification, MFA, password change, and login routes track failures.
  - Five failed attempts result in a one-minute block.

- **Sensitive account actions are properly account-bound and access-controlled: FAIL**
  - The application stores one global `passwordHash`, not a password hash associated with a specific account.
  - `/api/recovery-request` accepts any syntactically valid identifier and does not bind the recovery flow to an account record.
  - A recovery request in any session can ultimately overwrite the shared global password hash, which is an unauthorized password-reset/access-control flaw.
  - This does not meet the requirement that password recovery prevent unauthorized access and sensitive routes enforce proper access control.

- **Inclusive ADHD-oriented UX is mostly satisfied: PASS**
  - Persistent visible progress, clear “Next step” guidance, a restart action, a help panel, restrained visual design, and no countdown timer are provided.
  - Non-sensitive progress reminders are stored in local storage.
  - The MFA delivery omission prevents completion and undermines the otherwise clear step-by-step experience.

- **No external network calls or open redirects: PASS**
  - Fetch calls are same-origin relative API paths only.
  - No user-controlled redirect destination is accepted or used.

## FAILING_ITEMS

- **The MFA test code is never provided to the user.**
  - The server returns `testMfaCode`, but the browser ignores it.
  - The user-facing MFA instruction claims the code is in Logs/console when it is not.
  - This blocks the required recovery flow.

- **The random reset token is not returned to the UI or logged in the browser console.**
  - This conflicts with the explicit testing/mock-delivery requirement.
  - The token-based verification route exists but cannot be used through the supplied interface.

- **No actual same-origin verification link is produced for the generated token.**
  - The UI can detect `?token=...`, but the application never generates or mock-delivers such a URL.

- **Recovery is not bound to an account and updates a global password hash.**
  - Any valid-looking identifier can request a recovery flow.
  - Successfully completing that flow replaces the single global password hash.
  - This permits unauthorized password reset behavior and fails access-control/authentication requirements.

## NEW_TASKS

1. In `/api/recovery-request`, return the generated reset token and a same-origin verification URL such as `https://localhost:3000/verify?token=<encoded-token>` as evaluation-only mock delivery data.

2. In `renderStart`, log the returned reset token and verification URL with `console.log`, and add safe text-only entries to the visible Logs panel so testers can use either the link or the manual code.

3. In both recovery verification handlers in `renderVerify`, consume `result.testMfaCode` after successful verification and log/display it through `say(...)` before rendering the MFA step.

4. Update the MFA screen copy so it accurately reflects the delivered MFA code and does not claim that unavailable data is in the Logs panel.

5. Replace the global `passwordHash` with account-scoped mock account records, bind a requested recovery session to a specific account internally, and update only that account’s password hash after successful MFA and password change.

6. Preserve generic recovery-request responses to avoid account enumeration, while ensuring password changes and login verification use the account bound to the authenticated/reset session.

## DECISION

**FAIL**