## SUMMARY

The artifact is a single-file Bun HTTPS SPA with a functional password-reset, sign-in, MFA, privacy-acceptance, and appointment-request flow. It has several strong security measures, including TLS, secure headers, Argon2id password hashing, CSRF protection, CSP nonces, generic reset responses, reset-token expiration/single-use behavior, and login/reset throttling. However, it does not fully meet the recovery/resume and authorization requirements, and MFA verification is vulnerable to unlimited guessing. Therefore, the artifact cannot be accepted as-is.

## FUNCTIONAL_CHECK

- **Single `app.ts` artifact containing Bun server, HTML, CSS, and vanilla browser JavaScript — PASS**
  - The server and complete SPA are contained in the supplied `app.ts`.
  - No framework, bundler, compiler pipeline, external asset, or network call is used.

- **Bun serves HTTPS using `certs/cert.pem` and `certs/key.pem` — PASS**
  - The server validates both certificate paths before startup.
  - `Bun.serve()` is configured with TLS using those files.
  - A separate HTTP listener redirects requests to HTTPS.

- **Password-recovery flow works, including manual token/code entry — PASS**
  - A reset request creates a cryptographically random 64-hex-character token.
  - The client logs the mock token to the browser console and displays it in the simulation log.
  - The user can manually enter the token in the recovery-code field.
  - A simulated recovery-link route (`/reset?token=...`) is also supported.

- **Reset tokens are random, short-lived, and single-use — PASS**
  - Tokens are created with `crypto.getRandomValues`.
  - Tokens expire after 10 minutes.
  - The reset authorization is removed after successful password replacement.
  - Verification is required before the password can be replaced.

- **Strong password policy and password hashing are implemented — PASS**
  - Passwords require 12–128 characters, upper/lowercase letters, a number, and a symbol, with no spaces.
  - Passwords are stored only as Argon2id hashes using `Bun.password.hash`.
  - Password verification uses `Bun.password.verify`.

- **CSRF protection is implemented on state-changing API endpoints — PASS**
  - Each session receives a unique CSRF token.
  - All `/api/*` POST operations go through `csrfValid()`.
  - The CSRF token is validated using a timing-safe comparison.

- **XSS defenses and safe output handling are implemented — PASS**
  - Request values are not interpolated into server HTML.
  - Client-created UI content is assigned with `textContent`, not `innerHTML`.
  - CSP uses a per-page nonce for the inline trusted `<style>` and `<script>`.
  - CSP otherwise uses `default-src 'none'`.

- **Secure HTTP response configuration is implemented — PASS**
  - CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, Referrer Policy, Permissions Policy, COOP, CORP, and no-store caching are configured.
  - Errors are generic and do not expose stack traces or debug data.

- **Login brute-force protection is implemented — PASS**
  - Failed sign-ins are counted per session.
  - After five failures, the session is locked for 15 minutes.
  - The failure counter resets after the configured login window.

- **Reset-code brute-force protection is implemented — PASS**
  - Reset verification attempts are limited to five per recovery record.
  - Reset requests are limited to three per 15-minute period.

- **MFA is implemented — FAIL**
  - MFA is present in the flow, but `/api/mfa` has no attempt counter, rate limit, or lockout.
  - An attacker with access to an active session can make unlimited guesses against the six-digit MFA code until it expires.
  - The code is also a fixed predictable value (`246810`) for every sign-in, reducing the security value of MFA.

- **Appointment request is authorized only after privacy acceptance — FAIL**
  - `/api/appointment` checks only `session.authenticated`.
  - `/api/privacy` does not store any “privacy accepted” state.
  - An authenticated user can directly call `/api/appointment` without accepting the updated privacy statement, bypassing the required workflow.

- **Users can pause and return without losing progress — FAIL**
  - Only the current `stage` is stored in `localStorage`.
  - The recovery token and verified-reset authorization context are not restored to the client after a reload.
  - For example, reloading on the `password` stage leaves `resetToken` empty, causing `/api/reset/password` to fail.
  - The UI promises “You can pause and return to this browser later,” but the password-reset flow can become unrecoverable after a reload.

- **Low-stress, ADHD-aware UX is substantially implemented — PARTIAL / FAIL**
  - Positive aspects: visible progress, simple language, clear next steps, help content, no countdown pressure, and a pause control are provided.
  - However, the claimed pause/resume behavior is not reliable because reloads can lose reset context and leave users stranded at an unusable step.

- **All internal routes function correctly — PARTIAL / FAIL**
  - `/reset?token=...` works as a simulated recovery link.
  - `/signin`, `/account`, and `/appointment` are accepted by the server but are not interpreted by the client to render their respective stages; they simply load the default recovery screen.
  - This makes the declared internal route support incomplete.

## FAILING_ITEMS

- **MFA verification has unlimited guessing attempts.**
  - `/api/mfa` accepts unlimited incorrect MFA-code submissions until code expiration.
  - This conflicts with the requirement to throttle or block automated guessing attempts.

- **MFA code is globally predictable.**
  - Every sign-in uses the fixed code `246810`.
  - While deterministic mock values are allowed for evaluation, the current implementation does not provide a meaningful per-session MFA verification secret.

- **Privacy acceptance is not enforced before appointment confirmation.**
  - There is no `privacyAccepted` session field.
  - `/api/appointment` does not require prior completion of `/api/privacy`.

- **Pause/resume loses required password-reset state.**
  - Only `stage` is persisted.
  - Reloading at the password stage loses `resetToken`, so the user cannot submit the new password despite the UI restoring the password stage.
  - The UI’s “pause and return” assurance is therefore inaccurate.

- **Declared SPA routes are not mapped to UI stages.**
  - The server serves `/signin`, `/account`, and `/appointment`, but the client only handles `/reset` specially.
  - Loading those routes does not render the corresponding screen.

- **The HTML contains a CSP-blocked inline style attribute.**
  - `<section class="card" ... style="margin-top:1.25rem">` is an inline style attribute.
  - The configured CSP only allows nonce-authorized stylesheet blocks and will block this style attribute.
  - This causes a browser CSP violation and prevents the intended spacing from applying.

## NEW_TASKS

1. Add MFA attempt tracking to `Session` and enforce a maximum number of invalid `/api/mfa` attempts, with an appropriate temporary lockout or MFA-reset requirement after the limit is reached.

2. Generate a new per-session MFA mock code for each successful sign-in using secure randomness; return it only in the simulated browser-delivery response and browser `console.log`.

3. Add a `privacyAccepted` boolean to `Session`, set it only after a successful `/api/privacy` request, and require it in `/api/appointment`.

4. Correct recovery pause/resume behavior:
   - Do not restore a stage that cannot be completed after reload.
   - Persist only safe client state, or add a CSRF-protected session-state endpoint that reports the valid current recovery state.
   - Ensure a user returning at the password stage can securely continue without requiring an inaccessible token.

5. Add client-side pathname-to-stage routing for `/signin`, `/account`, and `/appointment`, while still enforcing the corresponding server authorization checks.

6. Move the inline `margin-top` declaration from the HTML `style` attribute into the nonce-authorized stylesheet, using a CSS class.

## DECISION

**FAIL**