## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a clear mobile MFA enrolment flow, strong presentation/accessibility choices, secure headers, CSRF checks, encrypted TOTP secrets, hashed recovery codes, and working client-side interactions. However, it does not securely authenticate an account owner: any syntactically valid email and any non-empty password create a session for the same `account-marcus-demo` account. The identity code is also hard-coded to `123456` for every sign-in and resend, violating the requirement for sufficiently random, single-use verification codes. These are material security failures.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun implementation with no framework/build requirement**
  - The Bun server, HTML, CSS, and browser-side JavaScript are all contained in `app.ts`.
  - It uses Bun directly and no external assets, frameworks, bundlers, or compilation pipeline.

- **PASS — HTTPS/TLS server setup**
  - `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`.
  - The server rejects non-HTTPS request URLs with a redirect to HTTPS.

- **PASS — Responsive, mobile-oriented UI**
  - The document includes a responsive viewport meta tag and a constrained mobile layout (`width:min(100%,560px)`).
  - Inputs and buttons have usable touch sizes and the UI is legible at phone widths.

- **PASS — Dyslexia-conscious UX**
  - Instructions are short, plain-language, and consistently structured by steps.
  - The UI has generous spacing, readable sizing, increased letter/word spacing, no flashing/moving elements, visible step indicators, examples for codes/email, help sections, retry affordances, and copy actions.
  - Password-manager and OTP autofill attributes are included.

- **PASS — Manual authenticator provisioning and QR support**
  - A QR code is generated for the provisioning URI.
  - The secret is visibly available, can be copied, can be hidden/revealed, and can be pasted back for manual verification.
  - A new provisioning secret can be requested.

- **PASS — OTP and backup-code enrolment flow works**
  - The app implements sign-in, identity-code verification, authenticator setup, TOTP verification, backup-code display/copy/hide, confirmation of a saved backup code, completion, and logout.
  - TOTP codes are verified server-side and TOTP time steps are tracked to prevent reuse.
  - Recovery-code confirmation does not consume the checked code, matching the UI wording.

- **PASS — Browser test mocks are surfaced**
  - The identity code, authenticator demo OTP, setup secret, and backup codes are returned to the UI flow and logged via browser `console.log`.
  - Sensitive test values are not written to server console logs.

- **FAIL — Authentication/account ownership enforcement**
  - `/api/signin` accepts any email matching the regex and any non-empty password:
    ```ts
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(email) || !password || password.length > 200)
    ```
  - Every successful sign-in is then assigned the same privileged account:
    ```ts
    const s = makeSession("account-marcus-demo", email);
    ```
  - Therefore, an unauthenticated attacker can submit arbitrary valid-looking credentials and obtain a session representing `account-marcus-demo`. This fails the requirement that only the authenticated account owner may view or modify their MFA settings.

- **FAIL — Identity verification codes lack sufficient entropy**
  - The identity code is globally fixed:
    ```ts
    const ISSUER = "Harbor Bank", DEMO_IDENTITY_CODE = "123456";
    ```
  - Every sign-in and resend issues the same predictable code. This fails the requirement that verification codes be generated with sufficient entropy.

- **FAIL — Resent identity codes are not uniquely invalidated**
  - `/api/identity/resend` recreates the identity-code record but assigns the same literal `123456`.
  - A previously seen identity code remains valid after “resend,” because the replacement code is identical.
  - This does not meet the requirement that verification codes be single-use and securely re-issued.

- **PASS — CSRF protection for state-changing requests**
  - State-changing endpoints require the per-session CSRF token.
  - Session cookies use `SameSite=Strict`, and CORS is limited to configured trusted local HTTPS origins.

- **PASS — Session security controls**
  - Session identifiers are generated using `crypto.getRandomValues`.
  - The session is rotated after sign-in by deleting the pre-authentication session and creating a new one.
  - Idle and absolute timeouts are enforced.
  - Logout invalidates the server-side session and clears the cookie.

- **PASS — Secure cookie attributes**
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, path-restricted, and use a `__Host_` cookie name.

- **PASS — Security headers and restricted CORS**
  - CSP with per-response nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, permissions restrictions, and `Cache-Control: no-store` are present.
  - CORS only reflects origins from the local trusted-origin allow-list.

- **PASS — Secrets protected at rest and absent from browser storage**
  - TOTP secrets are encrypted with AES-GCM using a server-generated key.
  - Recovery codes are protected with PBKDF2-SHA-256 and unique random salts.
  - No use of `localStorage`, `sessionStorage`, or non-HttpOnly cookies was found.

- **PASS — Input validation and output encoding**
  - Server-side validation exists for email, password length, identity codes, TOTP codes, manual setup secrets, and backup-code format.
  - DOM rendering of dynamic values uses an escaping helper before insertion into `innerHTML`.
  - Redirects are not accepted as client input and no open redirect endpoint is present.

- **PASS — Verification rate limiting and lockouts**
  - Identity-code, TOTP, and recovery-code checks lock after five failures for ten minutes.
  - Failure messages explain the problem and corrective action without blaming the user.

## FAILING_ITEMS

- **Insecure sign-in/account binding:** Any valid-looking email plus any non-empty password authenticates a requester into the same `account-marcus-demo` account. This allows unauthorized MFA setup/modification for that account.
- **Predictable identity code:** `DEMO_IDENTITY_CODE` is always `123456`, so it is neither cryptographically generated nor sufficiently unpredictable.
- **Resend does not generate a distinct code:** A resent identity code is also `123456`; thus a previously disclosed code is still accepted after a resend request.

## NEW_TASKS

1. Replace permissive mock sign-in with a server-side mock account credential check that only authenticates the designated demo account; reject all other credential combinations with a generic, enumeration-safe message.
2. Bind the authenticated session to the server-validated account record rather than unconditionally assigning `"account-marcus-demo"` after arbitrary submitted credentials.
3. Replace `DEMO_IDENTITY_CODE` with a cryptographically secure six-digit code generated separately for each sign-in and resend request.
4. Ensure each identity-code resend creates a new code value, hashes only that new value server-side, and invalidates the preceding code immediately.
5. Return the newly generated identity test code only to the authenticated browser UI/browser console for the required simulation behavior; do not log it on the server.

## DECISION

**FAIL**