## SUMMARY

The artifact has a strong server-side security structure: TLS, secure cookies, CSRF checks, session rotation, authorization based on server-side session identity, rate limiting, encrypted TOTP secrets, hashed recovery codes, and security headers are largely implemented correctly. However, the client-side script contains a JavaScript syntax error (`return.onclick`) that prevents the entire SPA from loading or functioning. There are also functional and security/UX issues, including a non-functional decorative QR code, an unauthenticated MFA-state disclosure, and sensitive debug data rendered in the page.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` Bun application with inline HTML, CSS, and JavaScript — PASS**
  - The server, HTML template, CSS, and browser JavaScript are contained in one `app.ts`.
  - It uses Bun directly and has no framework, bundler, compiler step, or external assets.

- **TLS using the supplied certificate paths — PASS**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The application is served over TLS and includes HSTS.

- **No external network calls — PASS**
  - Client requests use same-origin `fetch()` calls only.
  - No third-party scripts, fonts, images, QR libraries, or network resources are loaded.

- **Mobile-responsive, legible dyslexia-friendly UI — FAIL**
  - The CSS is generally mobile-oriented and uses generous sizing/spacing.
  - However, the browser script fails to parse, so the intended UI never renders beyond “Loading your secure page…”.
  - A non-functional app cannot satisfy the required enrolment UX.

- **Identity confirmation, authenticator provisioning, OTP verification, recovery-code generation, recovery-code checking, and logout must work — FAIL**
  - The client script contains `return.onclick=...` in both `confirmAuthenticator()` and `recoveryCheck()`.
  - `return` is a reserved JavaScript keyword, making this a syntax error. Because JavaScript parsing fails before execution, none of the SPA flow runs.
  - Additionally, after the parse issue is fixed, `identity()` uses `start.onclick`, but `start` is also the name of the `async function start()` declaration. This targets the function object rather than reliably targeting the button, leaving the “Start identity check” button without its intended event handler.

- **Authenticator QR option must correspond to the provisioning URI, with manual-secret support — FAIL**
  - Manual-secret reveal and copy controls exist.
  - The rendered “QR code” is only a decorative pseudo-random grid. It does not encode `provisioningUri`, cannot be scanned by an authenticator app, and therefore is not a valid QR provisioning option.
  - Labeling it as an authenticator setup QR code is misleading.

- **Copy-to-clipboard support and browser autofill support — PARTIAL / FAIL**
  - Copy buttons and OTP autofill attributes are present.
  - The fatal client-side syntax error prevents those controls from being rendered or used.
  - Therefore the requirement is not functionally met.

- **Short, plain-language, low-pressure instructions with retry/help support — FAIL**
  - The intended wording, examples, hints, retries, and lack of reading timers are good.
  - Since the SPA does not execute, users cannot access those interfaces or retry flows.

- **Server-side authorization and IDOR prevention on MFA actions — PASS**
  - MFA records are keyed only to the server-side authenticated account fixture.
  - MFA endpoints derive identity from the HttpOnly session rather than accepting a user/account identifier.
  - Manipulated user identifiers cannot be supplied to select another account.

- **Only authenticated account owner may view MFA settings — FAIL**
  - `GET /api/session` is available to unauthenticated visitors and returns:
    - `mfaEnabled: !!mfaRecords.get(account.id)?.enabled`
  - This discloses whether the fixed account has MFA enabled before authentication. MFA state should not be returned for an unauthenticated session.

- **CSRF protection for state-changing requests — PASS**
  - State-changing API routes require an `X-CSRF-Token` matching the server-side session token.
  - Origin validation is also performed.
  - Cookies use `SameSite=Strict`.

- **Secure security headers and clickjacking protection — PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, referrer policy, and permissions policy are present.
  - Nonces are applied to the inline style and script blocks.

- **Secure session management — PASS**
  - Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Session identifiers are regenerated after proof completion.
  - Idle and absolute expiration are enforced.
  - Logout invalidates the server session and clears the cookie.

- **OTP and recovery-code cryptographic protections — PASS**
  - TOTP secrets are generated with `crypto.getRandomValues`.
  - TOTP secrets are AES-GCM encrypted in memory at rest.
  - Recovery codes are generated using CSPRNG and stored as peppered SHA-256 hashes.
  - TOTP codes are time-based and are prevented from reuse through `usedSteps`.
  - Recovery codes are consumed upon successful use.

- **Rate limiting and lockout for failed verification — PASS**
  - Identity proof, authenticator verification, and recovery-code verification all have failure counters and temporary lockouts.
  - Error text gives the user a clear action and wait time.

- **No sensitive values in logs or visible debug UI — FAIL**
  - The browser code logs test OTPs and recovery codes as required for mock testing, but it also renders those log entries inside an always-open `<details class="logs" open>` element.
  - This places sensitive OTPs and recovery codes visibly in the application UI, adds clutter, and functions as an exposed debug panel.
  - Browser-console mock logging may be retained only to satisfy the explicit testing requirement, but sensitive values must not additionally be rendered in-page.

- **Input validation and output encoding — FAIL**
  - OTP and recovery-code formats are server-side validated.
  - However, the client `esc()` function has an incorrect escaping map:
    - It maps a double quote (`"`) to `&#39;`, which is an apostrophe entity.
    - It does not escape an apostrophe (`'`) at all.
  - The helper should correctly encode `&`, `<`, `>`, `"`, and `'` for its actual HTML contexts.

- **Internal navigation and screen transitions work — FAIL**
  - Screen changes are implemented as JavaScript-rendered SPA transitions rather than URL links, which is acceptable in principle.
  - Due to the fatal JavaScript syntax error, none of these transitions function.

- **Zero-compilation compliance — PASS**
  - Bun can directly run the provided TypeScript file.
  - No separate build or asset compilation process is required.

## FAILING_ITEMS

- The browser JavaScript has a fatal syntax error at `return.onclick=...` in two functions. This prevents all client-side code from parsing and running.
- The identity-start event binding conflicts with the declared `start()` function. `start.onclick` refers to the function binding instead of the intended element ID, so the button will not be wired correctly even after the syntax error is fixed.
- The displayed QR code is decorative and does not encode the generated `otpauth://` provisioning URI.
- `GET /api/session` reveals the account’s MFA-enabled state to unauthenticated users.
- Sensitive mock OTP and recovery-code log data is displayed in an in-page, always-open debug log panel.
- The HTML escaping utility incorrectly handles quotation marks and is not a correct contextual output-encoding helper.
- Because the SPA does not run, the required enrolment, verification, copy, retry, recovery, logout, accessibility, and mobile UX flows are currently unusable.

## NEW_TASKS

1. Replace both invalid `return.onclick` event bindings with references to explicitly selected elements, such as `document.getElementById("return")`, and verify the browser script parses without syntax errors.

2. Stop relying on global element-ID bindings throughout the client code. Query elements explicitly or use a helper such as `const byId = (id) => document.getElementById(id)`. In particular, rename either the `start()` function or the `id="start"` button and bind the identity button correctly.

3. Add a browser-level functional test of the complete flow: load page, start proof, complete proof, provision authenticator, verify OTP, save recovery codes, use one recovery code, regenerate codes, and log out.

4. Replace the decorative QR grid with a standards-compliant QR-code generator implemented locally in the single file, encoding the exact returned `provisioningUri`. Keep manual-secret reveal/copy as the fallback.

5. Modify `/api/session` so unauthenticated sessions do not receive `mfaEnabled` or any other account MFA state. Return MFA status only after `session.userId === account.id`.

6. Remove the visible in-page debug log panel and `logLines` UI rendering. Retain only the required browser `console.log` mock output, and ensure no production/server logging outputs secrets.

7. Correct the `esc()` helper to encode all required characters accurately: `&`, `<`, `>`, `"`, and `'`. Use it consistently for any dynamically inserted HTML text or attributes.

8. Re-test the application under CSP after the event-binding and QR changes to confirm all inline script/style behavior still works with the generated nonce.

## DECISION

**FAIL**