## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a strong overall structure: inline vanilla JS, CSP nonces, secure cookies, CSRF checks, Argon2 password hashing, token expiry/single-use handling, throttling, MFA, accessible progress UI, and browser-side simulated delivery logs. However, it does not fully meet the security and recovery-flow requirements. Most importantly, the globally disclosed recovery-channel code allows an attacker who knows or guesses the account email to reset the password. There are also broken restart/re-entry flows and a literal violation of the requirement that mocks use browser `console.log`.

## FUNCTIONAL_CHECK

- **PASS — Single `app.ts` deliverable with Bun server, HTML, CSS, and vanilla browser JS**
  - The server, page template, styles, and client-side logic are all contained in the supplied `app.ts`.
  - No framework, bundler, compiler, external asset, or external network call is used.

- **PASS — Bun HTTPS server uses the provided certificate locations**
  - The server checks for `certs/cert.pem` and `certs/key.pem`.
  - `Bun.serve` is configured with TLS material from those files.
  - The server fails safely if certificates are missing.

- **PASS — Security headers and secure session cookies are substantially configured**
  - HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and no-cache headers are present.
  - Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and scoped to `/`.
  - The HTML CSP uses a per-response nonce for the inline style and script.

- **PASS — CSRF protection is implemented for state-changing API routes**
  - All POST endpoints require a valid session, same-origin `Origin`, and a per-session CSRF token.
  - The CSRF token is randomly generated when the session is created.
  - State-changing endpoints, including recovery, login, MFA, privacy acceptance, logout, and abandonment, use the CSRF/session guard.

- **PASS — XSS protections are appropriately implemented in the SPA**
  - Dynamic client content is rendered through `createTextNode` / `textContent`-equivalent DOM creation rather than `innerHTML`.
  - User-controlled values are not interpolated into HTML.
  - Reset token links use `encodeURIComponent`.
  - CSP restricts scripts to the generated nonce and denies external/default sources.

- **FAIL — Password recovery prevents unauthorized access**
  - The approved-channel confirmation code is the globally fixed value `135790`.
  - The code is explicitly displayed in the UI: `Mock demo confirmation code: 135790.`
  - An attacker who knows or guesses `helena.patient@hospital.test` can submit that email, enter the publicly shown code, receive a valid reset token, and set a new password.
  - This defeats the intended recovery-channel authorization control and violates the requirement that password recovery prevent unauthorized access.

- **FAIL — The portal does not fully prevent account enumeration / exposure through recovery behavior**
  - Although `/api/recovery/start` returns a generic response, the subsequent channel-confirmation behavior distinguishes a real account from a nonexistent account.
  - For the real account plus the public code, `/api/recovery/channel` returns `{ ok: true, token }`; for an unknown account it returns a generic failure.
  - Since the supposed channel code is public, this becomes a practical account-existence oracle.

- **PASS — Reset tokens are cryptographically random, short-lived, session-bound, and single-use**
  - Reset tokens are generated using `randomBytes`.
  - Only a SHA-256 digest is retained server-side.
  - Tokens expire after 15 minutes, are invalidated after password reset, and cannot be reused.
  - Verification and password changes require the recovery state and matching session-held token digest.

- **PASS — Password policy, password hashing, login throttling, and MFA are implemented**
  - The password policy requires 12+ characters, uppercase, lowercase, digit, symbol, and no spaces.
  - New passwords are stored with `Bun.password.hash(..., { algorithm: "argon2id" })`.
  - Login and recovery/MFA verification attempts have server-side attempt limits and lock periods.
  - MFA is required after successful login before privacy acceptance.

- **PASS — Recovery-code link and manual code submission are supported during an active browser session**
  - The simulated reset link routes to `/recovery/verify?token=...`.
  - The verification view permits typing or pasting a recovery code manually.
  - The reset token is logged in the browser console when delivery is simulated.

- **FAIL — Pausing/returning can leave the user unable to continue manually**
  - If `sessionStorage` is cleared or unavailable while the server still has `stage === "recovery"`, bootstrap restores the user to the `delivery` screen.
  - `deliveryView()` only renders actions when `sessionStorage.getItem(tokenKey)` exists.
  - Therefore, the user may see no “Enter a code manually” button even though the server-side recovery remains valid and the user may have the code from the simulated message.
  - This conflicts with the requirement to allow users to pause and return without losing progress, and with the manual-code fallback requirement.

- **FAIL — “Restart password recovery” is broken after a successful password reset**
  - On the success screen, “Restart password recovery” only changes client state to `start`.
  - The server session remains at `resetComplete`.
  - `/api/recovery/start` only allows stages `anonymous`, `channel`, or `mfaExhausted`, so the next submitted recovery form returns a generic error.
  - The same issue occurs when the user chooses “Reset password instead” from the login screen after reset completion.
  - This violates the requirement that internal navigation/actions function correctly.

- **FAIL — Not all simulated mock events use browser `console.log`**
  - The requirements explicitly state: “All mocks via `console.log` IN THE BROWSER.”
  - The artifact contains multiple server-side mock logs such as `console.log("SIMULATED SERVER: ...")`.
  - While reset delivery and MFA delivery are also logged in the browser, the implementation does not comply literally with the requirement that all mocks be browser-console based.

- **PASS — ADHD/inclusivity-focused UX is generally well addressed**
  - The UI provides visible progress, “Next step” reminders, clear labels, simple wording, a persistent help/safety route, accessible focus styling, and low-distraction layout.
  - It avoids browser-side countdowns and unexpected redirects.
  - However, the broken return/manual-entry state prevents full compliance with the pause-and-return requirement.

- **PASS — No obvious TypeScript/Bun syntax or runtime construction error is present**
  - The code is structurally valid TypeScript for Bun’s direct TypeScript execution.
  - `Bun.file`, `Bun.serve`, `Bun.password.hash`, and `Bun.password.verify` are used in a manner compatible with Bun.
  - The mutable `INTERNAL_ACCOUNT.passwordHash` property is valid despite `INTERNAL_ACCOUNT` being declared with `const`.

## FAILING_ITEMS

- The globally displayed deterministic channel code (`135790`) is sufficient to authorize reset-token creation for the known account, enabling unauthorized password resets.
- Recovery flow behavior can be used to distinguish a valid account from an invalid account after the public channel code is supplied.
- A recovered `delivery` state with no browser-held token provides no manual-entry action, even though a valid recovery token may still exist and the user may have recorded it.
- “Restart password recovery” after the reset completion screen changes only the client view; the server state blocks the next recovery request.
- “Reset password instead” from login can similarly navigate to a recovery form that the backend refuses because the session remains `resetComplete`.
- Server-side `console.log("SIMULATED SERVER: ...")` entries violate the explicit requirement that all mocks be logged in the browser console.

## NEW_TASKS

1. Replace the globally displayed recovery-channel code with a recovery authorization mechanism that cannot be used by an arbitrary requester to reset a known account; ensure the mock remains deterministic/testable without exposing a universal reset credential in the UI.

2. Make recovery responses non-enumerating across the complete recovery flow, including the approved-channel step; do not return a reset token or materially different response merely because the submitted email belongs to the account.

3. Update the delivery/recovery-resume UI so “Enter a code manually” is always available whenever the server reports an active `recovery` stage, even when `sessionStorage` lacks the token.

4. Implement a CSRF-protected restart/abandon action that resets a `resetComplete` session to an allowed recovery-start state, and call it before navigating to the recovery-start form from both “Restart password recovery” and “Reset password instead.”

5. Remove server-side simulated-event `console.log` calls or replace them with browser-side logging for the relevant simulated delivery/status events, consistent with the browser-console-only mock requirement.

## DECISION

FAIL