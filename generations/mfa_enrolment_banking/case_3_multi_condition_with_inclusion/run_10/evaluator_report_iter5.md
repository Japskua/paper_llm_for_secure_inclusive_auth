## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a generally strong mobile-oriented MFA flow, secure cookie settings, CSRF checks, session rotation, input validation, and clear dyslexia-aware UI writing. However, it does not fully meet the requirements: the displayed “QR” image is not a usable QR code, authenticator OTP verification is not time-bound, lockout protections can be bypassed by re-requesting/provisioning codes, and a page refresh during MFA setup incorrectly routes the user to completed MFA settings before setup is complete.

## FUNCTIONAL_CHECK

- **Single `app.ts` file containing Bun server, HTML, CSS, and browser JavaScript — PASS**  
  The entire implementation is in one TypeScript file and Bun directly serves the generated HTML.

- **No frameworks, bundlers, compilers, external assets, or external network calls — PASS**  
  The artifact uses Bun, vanilla browser JavaScript, inline CSS, and no external resources.

- **Bun HTTPS server uses the supplied TLS certificate paths — PASS**  
  The server reads `certs/cert.pem` and `certs/key.pem` and supplies them to `Bun.serve({ tls: ... })`.

- **Responsive, mobile-readable, dyslexia-aware UI — PASS**  
  The layout has a constrained mobile-width shell, legible font sizing, generous line spacing, plain language, short examples, help text, and avoids animation/clutter.

- **Clear step progression and primary actions — PASS**  
  The sign-in, identity, authenticator, recovery-code, and completion screens use a predictable order and prominent primary buttons.

- **Browser autofill and copy support — PASS**  
  Email/password/OTP autocomplete values are included, and setup/recovery-code copy controls include a selection fallback if Clipboard API access fails.

- **Manual secret entry is supported when authenticator provisioning is offered — PASS**  
  The UI lets the user optionally paste the authenticator setup secret before verification.

- **Usable QR-code provisioning option — FAIL**  
  `fakeQr()` creates a pseudo-random 17×17 visual pattern, not a standards-compliant QR code encoding the `otpauth://` URI. An authenticator app cannot scan it. The UI describes it as a “QR setup option,” so it does not meet the offered QR-code requirement.

- **Identity verification works with deterministic browser-console mock value — PASS**  
  The identity OTP is returned only to the authenticated session, logged in the browser console, is six digits, expires after ten minutes, and becomes single-use after successful verification.

- **Authenticator verification works — PARTIAL / FAIL**  
  The deterministic authenticator OTP can complete the flow, but it is not time-bound. `DEMO_AUTH_OTP` is accepted indefinitely after provisioning until it is used. This fails the requirement that verification OTPs be time-bound.

- **Verification lockout and rate limiting — FAIL**  
  Identity lockout can be bypassed because `/api/identity/request` resets `identityFailures` to zero on every re-request. MFA lockout can likewise be bypassed because `/api/mfa/provision` resets `otpFailures`, `otpLockedUntil`, and `otpUsed` whenever it is called. This permits unlimited grouped attempts.

- **Recovery codes are single-use — PASS**  
  A matching recovery-code hash is removed from the account record after successful use.

- **Recovery code regeneration safely replaces prior codes — PARTIAL / FAIL**  
  Regeneration replaces the stored list, but always recreates the exact same fixed values. Previously used or exposed demo codes can become valid again after regeneration. This does not provide newly generated recovery codes with sufficient entropy.

- **Session ownership / IDOR protection — PASS**  
  Server endpoints derive account identity from the HttpOnly session and do not accept a user/account identifier from the client.

- **CSRF protection on state-changing endpoints — PASS**  
  State-changing requests require a matching `X-CSRF-Token`; cookies are `SameSite=Strict`, and trusted origins are checked.

- **Secure cookie and session handling — PASS**  
  The session cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, and the `__Host-` prefix. Sign-in rotates the session ID; idle/absolute timeouts and logout invalidation are implemented.

- **Security headers and restrictive CORS — PASS**  
  CSP with nonce, HSTS, `nosniff`, clickjacking protections, referrer policy, cache prevention, and trusted-origin CORS behavior are present.

- **Sensitive values are not stored in browser storage or URL query strings — PASS**  
  The implementation does not use `localStorage` or `sessionStorage`, and secrets/codes are not inserted into URL query parameters. Browser-console test output is explicitly required by the brief for this academic mock.

- **Secret and recovery-code protection at rest — PARTIAL / FAIL**  
  The OTP secret is AES-GCM encrypted and recovery codes are PBKDF2 hashed, which is good. However, provisioning and recovery-code generation use fixed constants rather than cryptographically secure per-event values. In particular, regenerated recovery codes are predictable and repeatable.

- **Input validation and DOM XSS prevention — PASS**  
  Server-side validators exist for email, phone, OTP, setup key, and recovery codes. The client renders dynamic text using `textContent`, reducing DOM XSS risk.

- **Correct continuation after refresh during enrolment — FAIL**  
  After identity verification, the session stage is `"verified"` even if MFA has not yet been enabled. `/api/bootstrap` then routes any `"verified"` session directly to `"settings"`. Refreshing during Step 3 therefore skips setup and shows “Your authenticator app is active” even when `mfaEnabled` is false, leaving the user without a normal route to complete enrolment.

- **Generic production error handling — PASS**  
  The top-level server catch returns a generic error message and does not expose stack traces.

## FAILING_ITEMS

- The QR display is decorative pseudo-random output rather than a scanner-readable QR code containing the provisioning URI.
- Authenticator verification codes are not time-bound; the static code remains valid indefinitely after provisioning.
- Identity verification lockout is reset by every `/api/identity/request` call, allowing repeated failed-code attempts without reaching a durable lockout.
- MFA verification lockout is reset by every `/api/mfa/provision` call, allowing repeated MFA OTP attempts without a durable lockout.
- Recovery-code regeneration recreates the same predictable code set, allowing old known codes to become valid again.
- OTP secrets and recovery codes are fixed constants rather than securely generated per provisioning/regeneration event.
- Refreshing after identity verification but before MFA completion routes the user to MFA settings and incorrectly claims the authenticator is active.

## NEW_TASKS

1. Replace `fakeQr()` with an in-browser, standards-compliant QR encoder that encodes the returned `otpauth://` provisioning URI and can be scanned by authenticator applications.

2. Add an authenticator verification expiry timestamp to `Session`; set it during provisioning and reject MFA verification after the configured expiry with a clear retry/provision-again message.

3. Preserve identity-verification failure counts and lockout state when sending a replacement identity code; add delivery/request throttling so re-requesting a code cannot bypass verification-attempt lockout.

4. Prevent `/api/mfa/provision` from clearing OTP failure/lockout state while an active lockout exists; apply a provisioning/request limit so repeated provisioning cannot bypass MFA verification lockout.

5. Generate a new authenticator secret and a new set of recovery codes using `crypto.getRandomValues` for each provisioning/regeneration event; hash the new recovery codes with unique random salts before storage. Return the generated academic test values only to the authenticated browser and browser console as required.

6. Update bootstrap/session-routing data to include whether `mfaEnabled` is true. Route identity-confirmed but unfinished users back to authenticator setup, and only show active MFA settings when MFA setup has actually completed.

## DECISION

**FAIL**