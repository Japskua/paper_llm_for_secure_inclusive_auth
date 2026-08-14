## SUMMARY

The artifact is a single-file Bun HTTPS application with a responsive, dyslexia-aware MFA flow, server-side sessions, CSRF checks, encryption/hashing, rate limits, and simulated browser-console delivery of test values. However, it does not fully meet the functional requirements because the generated QR code cannot encode the supplied provisioning URI, “send a new code” does not actually issue a new identity code, and a page refresh can bypass the required backup-code completion flow.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, external assets, or external network calls.**  
  The server, HTML, CSS, and browser JavaScript are all in `app.ts`; it uses Bun’s native `serve`, `file`, and Web Crypto APIs.

- **PASS — HTTPS/TLS is configured using the required certificate paths.**  
  Bun is configured with `certs/cert.pem` and `certs/key.pem`, and non-HTTPS requests are rejected.

- **PASS — Mobile and dyslexia-inclusive UI requirements are substantially met.**  
  The UI has a constrained mobile layout, readable font fallbacks, increased line/letter spacing, plain language, icons, examples, generous spacing, no timers/animations, visible current step, help content, retry controls, and clear error text.

- **PASS — Identity, authenticator, and recovery verification are implemented server-side.**  
  Identity codes are hashed, time-bound, single-use, and lock after repeated failures. TOTP verification uses RFC-6238-style HMAC-SHA1 codes with a 30-second period and replay prevention. Recovery codes are hashed, expire, are single-use, and are rate-limited.

- **FAIL — The offered QR-code setup option is not reliably functional.**  
  `drawQR()` claims to build a Version 5-L QR code with a fixed capacity of 108 data codewords. The generated `otpauth://` URI is substantially longer than that capacity (roughly 140+ bytes). The encoder silently truncates data during matrix placement, producing a QR code that will not contain the complete provisioning URI and may not scan or provision correctly.

- **FAIL — “Send a new code” does not actually send a new identity code.**  
  `/api/identity/send` reuses the existing unexpired challenge and recalculates the same deterministic identity code. The UI button says “Send a new code,” but the previously issued code remains valid and no replacement code is created. This conflicts with the requirement to let users re-request codes and with the UI wording.

- **FAIL — Backup-code enrolment can be skipped after a refresh.**  
  MFA is marked enabled immediately after authenticator confirmation. On refresh, `/api/state` reports `mfaEnabled: true`, and `boot()` routes directly to the success screen. A user can therefore bypass generating, saving, and checking backup codes, despite those being a required part of the enrolment flow.

- **PASS — Copy and manual authenticator setup options are provided.**  
  The setup secret can be copied and manually entered, and backup codes can be copied. The provisioning secret and test OTP are returned to the browser and logged in the browser console as required for the mock/testing scenario.

- **PASS — Server-side authorization and IDOR resistance are implemented for MFA endpoints.**  
  MFA endpoints derive the account solely from the authenticated session’s `userId`; no client-provided account or user identifier is accepted for MFA operations.

- **PASS — CSRF protections are applied to state-changing endpoints.**  
  State-changing API calls require the session-specific `X-CSRF-Token`; session cookies are `SameSite=Strict`. Origin validation additionally restricts supplied origins to trusted local HTTPS origins.

- **PASS — Secure headers and session-cookie protections are implemented.**  
  The application sends CSP with a nonce, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and restrictive permissions/referrer policies. Session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **PASS — Secrets and recovery codes receive appropriate mock at-rest protection.**  
  TOTP secrets are AES-GCM encrypted in the server-side account record; recovery codes are generated with `crypto.getRandomValues` and stored only as pepper-protected SHA-256 hashes.

- **PASS — Input validation, output handling, and redirect safety are adequate.**  
  Inputs are validated on the server, there are no SQL queries, no external redirects, and values inserted into dynamic DOM elements that could be sensitive are generally assigned through `textContent`.

- **PASS — Session and authentication controls are substantially implemented.**  
  Session IDs rotate at login, sessions have idle and absolute expiry handling, logout invalidates the session, and failed sign-in/code attempts are rate-limited with lockout behavior. Login failures use generic messages to avoid account enumeration.

- **FAIL — Requirement-to-code comments are incomplete.**  
  There are some broad comments, but the file does not clearly map the implementation sections back to all specified security and UX requirement sections as requested. For example, CSRF, authorization, secure headers, validation, and session lifecycle controls are not individually documented with requirement mappings.

## FAILING_ITEMS

- The QR encoder uses a fixed Version 5-L capacity that is too small for the generated authenticator provisioning URI. The QR output is truncated and cannot be relied upon for authenticator provisioning.
- The “Send a new code” action reuses the old identity challenge/code instead of invalidating it and issuing a replacement code.
- Refreshing after authenticator confirmation routes the user to completion, even if backup codes have not been generated, saved, or checked.
- Code comments do not clearly map all major security and UX implementation areas to the numbered requirement sections.

## NEW_TASKS

1. Replace `drawQR()` with a standards-compliant QR implementation that selects a QR version/error-correction layout large enough for the complete generated `otpauth://` URI, including correct capacity, block interleaving, error correction, and masking; verify the generated QR scans into the exact URI returned by `/api/authenticator/setup`.
2. Change `/api/identity/send` so a re-request invalidates the prior unexpired identity challenge and creates a new challenge/code; preserve lockout protections so re-requesting cannot bypass an active verification lockout.
3. Add explicit server-side enrolment state for backup-code progress, such as `recoveryGenerated` and `recoveryConfirmed`; set confirmation only after successful recovery-code verification.
4. Return backup-code enrolment state from `/api/state` and update `boot()` routing so users resume at backup-code generation or backup-code verification after refresh instead of being sent directly to the success screen.
5. Add concise comments identifying where Requirements 1–5 are implemented, including authorization/ownership checks, CSRF, headers/cookie policy, encryption/hashing, input validation/output encoding, and session/rate-limit controls.

## DECISION

FAIL