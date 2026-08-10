## SUMMARY

The supplied `app.ts` does not constitute a runnable artifact: it ends in the middle of the `/api/provision/test-otp` handler and has unclosed syntax. It also contains no visible HTML template, client-side JavaScript, SPA UI, or `serve(...)` implementation. While the visible server portion includes several promising security controls, the application cannot be validated or accepted in its current incomplete state.

## FUNCTIONAL_CHECK

- **PASS — Single-file structure is intended**
  - The submitted code is contained in `app.ts`.
  - However, it is incomplete and therefore does not satisfy the runnable single-file deliverable requirement.

- **FAIL — Bun server serves a functional mobile SPA**
  - No completed `serve(...)` call is present in the supplied artifact.
  - No HTML page, CSS, semantic structure, responsive mobile layout, or browser-side JavaScript is visible.
  - The source terminates during an API handler, so it cannot start.

- **FAIL — MFA enrolment flow works end-to-end**
  - The visible code begins to implement sign-in, identity verification, authenticator provisioning, and recovery-code storage.
  - However, the required client flow and the remainder of the API routes are absent from the submitted source.
  - There is no evidence that MFA setup verification, enablement, recovery-code display/copy/download, regeneration, logout, settings, or navigation links function.

- **FAIL — Simulated OTP delivery and authenticator verification work in the browser**
  - The requirements require test mock codes and recovery codes to be shown with `console.log` **in the browser**.
  - No client JavaScript is supplied, so browser logging cannot be confirmed.
  - The `/api/provision` endpoint returns `secret` to the UI regardless of `TEST_SIMULATION`, which improperly exposes the OTP seed outside explicitly enabled test simulation.

- **FAIL — Manual authenticator setup / QR support is provided**
  - The provisioning endpoint returns a `secret`, but there is no supplied UI that renders a QR code, provides a copy button, accepts a manually entered secret, or clearly supports manual submission.
  - The requirements explicitly require QR and copy-to-clipboard options and manual alternatives where a provisioning URI/QR code is offered.

- **FAIL — Accessible, dyslexia-inclusive mobile UX**
  - No UI/CSS exists in the supplied artifact to verify readable typography, generous spacing, plain-language instructions, examples, prominent current-step indicators, retry/re-request controls, static visual design, or mobile responsiveness.
  - No help/hints or clear primary-action-per-screen implementation is present.

- **PASS — Server-side session ownership is partially implemented**
  - Authenticated account access is derived from an `HttpOnly` cookie-backed session in `auth(req)`.
  - The account ID comes from the session rather than user-supplied request data, reducing IDOR risk in the visible endpoints.
  - Session idle and absolute expiry checks are implemented.

- **PASS — CSRF protection is partially implemented**
  - Authenticated `POST` requests require a CSRF token through `csrf(req, session, data)`.
  - The sign-in route also uses a one-time bootstrap ticket.
  - This is only a partial pass because the artifact is truncated and not all eventual state-changing routes can be reviewed.

- **PASS — Secure cookie attributes are configured**
  - The session cookie includes `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a bounded `Max-Age`.

- **PASS — Important security headers are configured**
  - The visible `headers()` function sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and `Cache-Control: no-store`.
  - Trusted localhost origins are allow-listed for CORS.

- **FAIL — Sensitive values are never exposed outside explicitly permitted browser test simulation**
  - `/api/provision` always responds with `{ secret, email }`, even when `TEST_SIMULATION` is false.
  - This violates the security requirement not to expose OTP seeds. The test-only exception described in the source comment is not consistently applied.
  - The client-side logging behavior required for the simulation cannot be verified because no client code is supplied.

- **PASS — Cryptographically secure generation and protected-at-rest storage are partially implemented**
  - OTP setup secrets, session IDs, CSRF tokens, verification codes, and recovery codes use `crypto.getRandomValues`.
  - OTP secrets are encrypted using AES-GCM.
  - Recovery codes are stored as per-code salted PBKDF2 hashes.
  - This can only be considered partial because the incomplete source prevents validation of all storage/use paths.

- **PASS — Verification-code expiry, single use, and lockout are partially implemented**
  - `Verify` includes expiration, a `used` flag, attempts, and lock duration.
  - `check()` invalidates successfully used codes, rejects expired codes, and locks after repeated failures.
  - TOTP verification logic is not visible in a completed handler due to source truncation.

- **FAIL — All input validation, endpoint authorization, and injection protections can be validated**
  - Some visible input validation exists for JSON, email, OTP, and recovery-code format.
  - The source is incomplete, so all endpoints and output rendering cannot be reviewed.
  - No HTML/client rendering code is available to validate contextual output encoding and DOM-XSS safety.

- **FAIL — TLS server configuration is complete and operational**
  - The code reads `certs/cert.pem` and `certs/key.pem`, but no completed Bun `serve` configuration is included.
  - Therefore, it cannot be confirmed that HTTPS/TLS is actually used to serve the application.

- **FAIL — No compilation/build tooling and direct browser execution are demonstrated**
  - The TypeScript/Bun approach is compatible with no bundler in principle.
  - But the file is syntactically incomplete and lacks the browser-delivered HTML/JS needed for direct operation.

## FAILING_ITEMS

- The submitted file is syntactically incomplete. It ends inside the `/api/provision/test-otp` route at `return reply(req,`, with unclosed blocks and no closing implementation.
- No Bun `serve(...)` implementation is present in the supplied artifact, so no server can run.
- No HTML template, inline CSS, or browser-side vanilla JavaScript SPA is present.
- No responsive mobile UI or dyslexia-supporting UX can be evaluated or used.
- Required browser-side mock `console.log` behavior for OTPs and recovery codes is not implemented in the supplied code.
- `/api/provision` exposes the authenticator secret regardless of `TEST_SIMULATION`, contrary to the stated test-only protection and the requirement to avoid exposing OTP seeds.
- The visible source does not demonstrate QR generation, provisioning URI handling, copy-to-clipboard controls, password-manager/autofill support, manual setup alternatives, recovery-code display/storage controls, or functional internal navigation.
- Because the source is truncated, completion and security of MFA verification, backup recovery, MFA settings, code regeneration, and logout cannot be verified.
- HTTPS cannot be validated because certificate files are read but no completed TLS server setup is supplied.
- Security review is necessarily incomplete: unshown routes cannot be checked for authorization, CSRF, validation, rate limiting, secret exposure, redirect safety, or error handling.

## NEW_TASKS

1. Complete `app.ts` so it is syntactically valid, including all open handlers, braces, and the application startup code.
2. Add a Bun `serve(...)` configuration in `app.ts` that serves the application over HTTPS using `certs/cert.pem` and `certs/key.pem`, with generic production-safe error handling.
3. Add the complete HTML document, responsive inline CSS, and vanilla browser JavaScript to `app.ts`; do not use external assets, frameworks, bundlers, or compilation steps.
4. Implement the complete mobile MFA SPA flow: sign-in, identity-code request/verification, authenticator provisioning, authenticator-code verification, MFA confirmation, recovery-code presentation, recovery-code verification, regeneration, settings, and logout.
5. Implement inclusive UI requirements: semantic landmarks, dyslexia-friendly readable typography, short instructions with examples, generous spacing, visible current step, one primary action per screen, easy help/retry/re-request controls, and no time-pressure or moving content.
6. Add provisioning URI/QR presentation, a visible manual setup key, copy-to-clipboard controls, and manual code-entry support; ensure the UI uses safe DOM APIs such as `textContent`.
7. Restrict OTP secret, OTP, and recovery-code exposure to the explicitly enabled test simulation path only. In that mode, log required mock values with browser `console.log`; never send or log them in normal mode.
8. Complete and review every API endpoint so each state-changing route enforces authenticated ownership, CSRF validation, input validation, rate limiting/lockout, safe error responses, and no secret/token leakage.
9. Add and validate TLS response behavior and all security headers on the actual served HTML and API responses.

## DECISION

**FAIL**