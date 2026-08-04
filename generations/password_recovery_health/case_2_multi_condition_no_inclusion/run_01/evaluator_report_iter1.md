## SUMMARY

The artifact is a single-file Bun/vanilla HTML-CSS-JS application with strong security-oriented structure: TLS, secure session cookies, CSRF validation, CSP nonces, server-side state, bcrypt password hashing, MFA, throttling, and safe DOM output handling are largely implemented correctly. However, the core password-recovery flow is non-functional because the server rejects every generated recovery code before verification. This also means the internal mock recovery link cannot complete its intended action.

## FUNCTIONAL_CHECK

- **PASS — Single-file app and zero-compilation compliance:** All server logic, HTML, CSS, and browser JavaScript are contained in `app.ts`. It uses Bun directly, without bundlers, frameworks, build tools, or external assets.

- **PASS — Bun TLS server uses the supplied certificate paths:** `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, and the application is intended to be served over `https://localhost:3000`.

- **PASS — HTTPS and key browser security headers are configured:** The HTML response includes HSTS, CSP with a per-response nonce, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, and no-cache headers.

- **PASS — Session cookies use appropriate security flags:** The session cookie is opaque and uses `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and a finite `Max-Age`.

- **PASS — CSRF protection is implemented for sensitive requests:** Every API action requires a session-specific CSRF token. The server validates it before processing `recover`, `verify`, `reset`, `mfa`, `signin`, or `privacy` actions.

- **PASS — Sensitive state is server-side and not controlled by client identifiers:** The client does not submit account IDs, usernames, authorization flags, or redirect URLs. Reset records are bound to the active server-side session.

- **PASS — User-controlled browser output is handled safely:** Dynamic UI messages and mock values are written with `textContent`; no user input is interpolated into HTML. The application does not use `innerHTML`, untrusted script loading, or external URLs.

- **PASS — Password policy and hashing are implemented:** Passwords require 12–128 characters with uppercase, lowercase, number, and symbol requirements. Passwords are hashed with Bun bcrypt at cost 12 and are not logged or persisted as plaintext.

- **PASS — MFA and sign-in protections are implemented:** A six-digit mock MFA code is generated securely, stored only as a hash, and checked with attempt throttling. Sign-in is also throttled after repeated failures.

- **PASS — Reset token construction is random, hashed, single-use, and time-limited:** Reset IDs and secrets are generated with `crypto.getRandomValues`, only the secret hash is stored, reset tokens expire after 15 minutes, and successful password reset marks the token as used.

- **FAIL — Recovery-code verification works:** The generated recovery code has the form `id.secret`, but `validCode()` only permits `[A-Za-z0-9_-]` and rejects the mandatory `.` separator. Therefore, every valid generated recovery code is rejected before the parser reaches the intended `split(".")` validation.

- **FAIL — The mock recovery link functions correctly:** The mock link correctly pre-fills the recovery code in the verification form, but submission always fails because the server-side `validCode()` validation rejects the dot-separated token format.

- **FAIL — End-to-end password recovery flow is functional:** Since verification cannot succeed, users cannot reach password reset, MFA verification, sign-in, or privacy-condition acceptance through the normal recovery flow.

- **PASS — Manual recovery code submission is present:** The verification screen provides a manual recovery-code input. Its UI is correct, but the backend validation defect prevents successful submission.

- **PASS — Browser-side mock logging is implemented:** Recovery and MFA mock codes are logged with `console.log` in browser JavaScript and mirrored in the on-page logs area. Password values are not logged.

- **PASS — Safe-authentication guidance is displayed:** The UI explicitly tells users not to share passwords, recovery codes, or security codes with staff or email senders.

- **PASS — No outgoing URL / open redirect behavior exists:** The application does not accept return URLs or redirect targets from the client and does not make external network calls.

## FAILING_ITEMS

- The recovery token format produced by the server is incompatible with the first validation check in the verification endpoint.
  - Generated code: `id.secret`
  - Current pre-validation: `^[A-Za-z0-9_-]{10,180}$`
  - Problem: the regular expression excludes `.`, so all valid generated codes are rejected as invalid or expired.

- Because recovery-code verification is blocked, the internal `#verify?code=...` mock recovery link cannot complete verification.

- Because recovery-code verification is blocked, the required password-reset journey is unusable end-to-end.

## NEW_TASKS

1. Update `validCode()` so it accepts the actual dot-separated recovery-code format, for example by allowing `.` in the preliminary character validation or by replacing the preliminary validation with the existing structured `id.secret` validation.

2. Verify that a generated `mockCode` can be:
   - submitted manually in the verification form, and
   - used through the `#verify?code=...` mock recovery link.

3. Run an end-to-end recovery test after the validation fix: recover → verify → reset password → MFA → sign in → accept privacy conditions.

## DECISION

**FAIL**