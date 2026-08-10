## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and accessibility work: secure headers, HttpOnly/Secure/SameSite cookies, CSRF checks, encrypted TOTP secret storage, hashed recovery codes, CSP nonces, responsive styling, mock values logged in the browser, and no external dependencies. However, a critical account lookup error makes every authenticated MFA endpoint fail after login. There is also a broken print button and a lockout bypass for identity verification. Therefore the artifact is not functionally acceptable.

## FUNCTIONAL_CHECK

- **FAIL — Authenticated user can complete the MFA enrolment flow.**  
  `Session.accountId` is set to `account.id`, but `accounts` is keyed by email:
  ```ts
  accounts.set(email, account);
  ...
  accountId: account.id
  ...
  const account = accounts.get(session.accountId);
  ```
  Consequently, `sessionFor()` cannot find the account after a successful login and returns a generic 401 response. This breaks `/api/identity/request`, `/api/identity/verify`, authenticator setup/verification, recovery-code actions, logout, and status.

- **PASS — The app is delivered as one `app.ts` file with Bun server, HTML, CSS, and vanilla browser JavaScript.**  
  No framework, bundler, compiler, or external assets are used.

- **PASS — HTTPS/TLS is configured for Bun using the required certificate paths.**  
  The server uses:
  ```ts
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }
  ```
  and includes HSTS.

- **PASS — Mobile-oriented UI and dyslexia-conscious visual design are substantially implemented.**  
  The UI uses a narrow mobile shell, large controls, readable font sizing, letter spacing, plain wording, generous whitespace, clear numbered steps, no animations, help panels, icons, and autocomplete/input mode attributes.

- **FAIL — The recovery-code print/save action works.**  
  In `recovery()`:
  ```js
  const print=btn("Print or save as PDF","small");
  print.onclick=()=>print();
  ```
  The local button variable shadows `window.print`. Clicking the button attempts to invoke the button element as a function and throws a runtime `TypeError`.

- **PASS — Simulated identity, authenticator, and recovery values are returned to the UI and logged in the browser.**  
  The browser `log()` function calls `console.log`, and simulated identity OTP, provisioning secret/URI/test OTP, and recovery codes are logged. This follows the explicit mock/testing deliverable.

- **FAIL — Verification-code lockout cannot be reliably enforced.**  
  `/api/identity/verify` locks a challenge after repeated failures, but `/api/identity/request` always replaces the challenge with a new one and resets attempts/lock state:
  ```ts
  account.identityChallenge = { code: "246810", expiresAt: ..., attempts: 0, lockedUntil: 0, used: false };
  ```
  A user can bypass the 10-minute lockout by requesting another code immediately.

- **PASS — TOTP verification is time-bound, single-use, and rate-limited once the account lookup issue is corrected.**  
  The implementation accepts a narrow TOTP window, tracks used counters, encrypts the stored secret, and locks after repeated failures.

- **PASS — Recovery codes are generated with cryptographically secure randomness, stored as salted verifiers, and consumed after use.**  
  `randomBytes()` is used for generation, `scryptSync()` creates per-code verifiers, `timingSafeEqual()` compares them, and accepted recovery codes are removed.

- **PASS — Server-side authorization and anti-IDOR design are present in intent.**  
  No user identifier is accepted from MFA endpoint requests; endpoints derive the account from the server-side session. However, the current account lookup defect prevents this design from functioning.

- **PASS — State-changing routes have CSRF protections.**  
  POST routes require same-origin requests and an `X-CSRF-Token`; login has a separate CSRF token tied to an HttpOnly Strict SameSite cookie.

- **PASS — Security response headers and cookie attributes are appropriately configured.**  
  CSP with nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and Secure/HttpOnly/SameSite=Strict cookies are implemented.

- **PASS — No external network calls or open redirects are present.**  
  The client fetches same-origin API routes only. No redirect target is accepted from user input.

- **PARTIAL / FAIL — Inclusive retry, reveal/hide, and confirmation behavior is incomplete.**  
  Retry and re-request controls are available in several stages, but sensitive displayed setup/recovery values do not have a hide/reveal control despite the requirement to let users reveal and hide codes. Also, the successful identity-verification response message is discarded by the client, so the next screen does not explicitly confirm that the identity check succeeded.

## FAILING_ITEMS

- Authenticated MFA API requests always fail because sessions store an account ID while the account map is indexed by email.
- The identity-code lockout can be bypassed by requesting a new code, which resets the failed-attempt count and lock state.
- The “Print or save as PDF” recovery-code button throws a runtime error because `print` shadows `window.print`.
- The UI lacks hide/reveal handling for displayed sensitive setup and recovery values.
- The UI does not display the successful identity-verification confirmation returned by the server.

## NEW_TASKS

1. Fix account retrieval so `sessionFor()` resolves accounts by the immutable account ID stored in `Session.accountId` (for example, maintain a separate `accountsById` map while retaining an email lookup map for login).
2. Change `/api/identity/request` so it does not replace a currently locked identity challenge; return a clear 429 error until `lockedUntil` has passed.
3. Fix the recovery print handler by renaming the button variable and calling `window.print()`.
4. Add accessible show/hide controls for the displayed authenticator setup secret and recovery codes, without persisting those secrets in browser storage.
5. Display a plain success notice after identity verification, using the server’s returned success message before or within the authenticator setup screen.

## DECISION

**FAIL**