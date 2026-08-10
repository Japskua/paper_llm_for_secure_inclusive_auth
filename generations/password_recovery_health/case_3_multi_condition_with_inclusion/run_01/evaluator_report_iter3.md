## SUMMARY

The artifact is a single-file Bun/TypeScript password-recovery SPA with TLS, CSP nonces, CSRF validation, Argon2id password hashing, reset-token expiry/single use, session-bound reset grants, visible recovery progress, manual code entry, simulated browser-console delivery logs, MFA, and protected privacy acceptance. The main security defect is that verification and MFA throttling are keyed by the attacker-controlled submitted code/token, allowing unlimited attempts by changing the submitted value on every request. This fails the brute-force protection requirements.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The server, HTML, CSS, and browser-side vanilla JavaScript are all contained in `app.ts`. It uses `Bun.serve` directly and imports no packages or external assets.

- **PASS — TLS/HTTPS configuration is present.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, matching the required certificate locations. The application advertises an HTTPS localhost URL.

- **PASS — Security headers and restrictive CSP are configured.**  
  Responses include HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, no-store caching, and a CSP using per-response script/style nonces. The client scripts are nonced and there are no external script sources.

- **PASS — CSRF protection is implemented for sensitive POST routes.**  
  Each session receives a random CSRF token. All `/api/*` POST routes require the token through `validCsrf`, and the session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, and path-scoped.

- **PASS — Password reset tokens are random, expiring, and single-use.**  
  Reset tokens and grants are generated with cryptographically random bytes. Reset tokens expire after 15 minutes, are deleted immediately after successful verification, and result in a separate reset grant that expires after 10 minutes and is bound to the session.

- **PASS — Password reset verification supports both a recovery link and manual entry.**  
  The simulated delivery provides a recovery link containing the token and also displays a manual code input. Opening the link populates the code field and keeps the user at the Verify step.

- **PASS — Password reset flow works end to end for the recognized mock account.**  
  The user can request a reset, verify the simulated code, set a compliant password, sign in with it, complete MFA, and accept the privacy statement.

- **PASS — Password policy and secure password storage are implemented.**  
  Passwords require at least 12 characters with upper- and lowercase letters, a digit, and a symbol. Passwords are hashed and verified with Bun Argon2id APIs; no plaintext password is stored.

- **FAIL — Automated verification/MFA guessing is not effectively throttled.**  
  Reset-code throttling is keyed as ``${token}|${ip}``, and MFA throttling is keyed as ``${code}|${ip}``. Because both token/code values are controlled by the requester, an attacker can submit a different invalid value per attempt and receive a new rate-limit bucket each time. This permits unlimited guesses and violates the requirements for brute-force blocking/throttling.

- **PASS — Login failures are throttled.**  
  Login attempts use a server-side limiter keyed by account and IP. Repeated failed password attempts are blocked for five minutes after exceeding the configured limit.

- **PASS — UI addresses the ADHD/inclusivity requirements.**  
  The flow has a persistent visible progress indicator, one task per screen, clear messages, a no-countdown reminder, stable server-resumable recovery state, low visual density, and an accessible help option at every stage.

- **PASS — User-derived UI output avoids DOM XSS sinks.**  
  The client writes dynamic content using `textContent`, `replaceChildren`, and DOM node creation rather than `innerHTML`. The recovery link is created from a controlled same-origin URL plus URL-encoded token data.

- **PASS — Privacy acceptance is access-controlled.**  
  `/api/privacy` requires `session.authenticated`; unauthenticated sessions receive a 403 response.

- **PASS — Simulated deliveries are visible in the browser console and UI.**  
  The reset token/link and MFA code are logged using browser-side `console.log` and shown in the UI Logs panel, satisfying the stated simulation/testing requirement.

## FAILING_ITEMS

- **Verification rate limits are bypassable.**  
  `/api/verify-reset` uses `const verificationKey = \`${token}|${ip}\`;`. A new fake token creates a new rate-limit key, so invalid-token guesses are not globally/per-session/per-IP throttled.

- **MFA rate limits are bypassable.**  
  `/api/mfa` uses `const mfaKey = \`${code}|${ip}\`;`. A new fake MFA code creates a new rate-limit key, so an attacker can make unlimited MFA guesses instead of being blocked after repeated failures.

## NEW_TASKS

1. Change `/api/verify-reset` throttling to use a non-attacker-controlled key, such as the client IP plus session ID (or at minimum client IP), rather than the submitted reset token. Keep the existing successful-verification limit clearing aligned with the new key.

2. Change `/api/mfa` throttling to use a non-attacker-controlled key, such as the client IP plus session ID or the authenticated/pre-MFA account/session context, rather than the submitted MFA code. Ensure all incorrect code attempts for the same MFA challenge contribute to the same limit.

## DECISION

**FAIL**