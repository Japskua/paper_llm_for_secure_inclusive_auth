# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun application that serves the complete responsive mobile MFA UI as inline HTML, CSS, and vanilla JavaScript, with no local modules, external assets, build steps, or network calls.",
    "Configure the Bun server to use `certs/cert.pem` and `certs/key.pem` for HTTPS, reject or redirect non-TLS traffic appropriately, and apply HSTS, CSP, nosniff, anti-clickjacking, and trusted-origin-only CORS headers on all responses.",
    "Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite session cookies; rotate identifiers on authentication, enforce idle and absolute expiry, and invalidate sessions on logout.",
    "Implement server-side authorization for every MFA route so each request derives the account identity only from the validated session and rejects missing, expired, manipulated, or guessed user identifiers.",
    "Add CSRF protection to every state-changing MFA request using a server-validated anti-CSRF token, and ensure client requests submit that token without placing it in URLs or browser storage.",
    "Implement the mobile sign-in and identity-verification flow with generic failure messages, validated inputs, internal-only redirect destinations, rate limits, and temporary lockout after repeated failed attempts.",
    "Implement authenticator enrolment that generates a cryptographically random shared secret, stores it protected at rest in memory, presents a simulated provisioning URI/QR representation, and permits manual secret entry or manual OTP submission.",
    "Implement deterministic mock TOTP verification that is time-bound and single-use, rejects replayed or expired codes, rate-limits failures with lockout, and logs the test OTP/provisioning information only in the browser console while returning required mock values to the UI.",
    "Implement MFA activation only after successful authenticator verification, with server-side state changes protected by authorization and CSRF validation.",
    "Generate cryptographically secure backup recovery codes when MFA is enabled or regenerated, store only protected representations at rest, display each plaintext code only during its authorized issuance screen, and log issued test codes only in the browser console.",
    "Implement backup-code verification so a recovery code is single-use, invalidates its stored representation after success, is rate-limited and lockable after failures, and never exposes codes in URLs, server logs, errors, or browser storage.",
    "Add semantic, accessible, mobile-legible screens for sign-in, identity verification, authenticator setup, OTP confirmation, backup-code storage confirmation, MFA settings, recovery verification, regeneration, and logout; ensure every internal navigation action resolves to a working route or client state.",
    "Validate all server inputs including email, phone, OTP, recovery code, CSRF token, and redirect target; contextually escape all rendered dynamic content and return generic production-safe errors without debug details.",
    "Add concise comments in `app.ts` mapping each security control and UI flow to the relevant numbered requirements, and ensure server-side logs never contain OTPs, seeds, recovery codes, or session tokens."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun application that serves the complete responsive mobile MFA UI as inline HTML, CSS, and vanilla JavaScript, with no local modules, external assets, build steps, or network calls.
- Configure the Bun server to use certs/cert.pem and certs/key.pem for HTTPS, reject or redirect non-TLS traffic appropriately, and apply HSTS, CSP, nosniff, anti-clickjacking, and trusted-origin-only CORS headers on all responses.
- Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite session cookies; rotate identifiers on authentication, enforce idle and absolute expiry, and invalidate sessions on logout.
- Implement server-side authorization for every MFA route so each request derives the account identity only from the validated session and rejects missing, expired, manipulated, or guessed user identifiers.
- Add CSRF protection to every state-changing MFA request using a server-validated anti-CSRF token, and ensure client requests submit that token without placing it in URLs or browser storage.
- Implement the mobile sign-in and identity-verification flow with generic failure messages, validated inputs, internal-only redirect destinations, rate limits, and temporary lockout after repeated failed attempts.
- Implement authenticator enrolment that generates a cryptographically random shared secret, stores it protected at rest in memory, presents a simulated provisioning URI/QR representation, and permits manual secret entry or manual OTP submission.
- Implement deterministic mock TOTP verification that is time-bound and single-use, rejects replayed or expired codes, rate-limits failures with lockout, and logs the test OTP/provisioning information only in the browser console while returning required mock values to the UI.
- Implement MFA activation only after successful authenticator verification, with server-side state changes protected by authorization and CSRF validation.
- Generate cryptographically secure backup recovery codes when MFA is enabled or regenerated, store only protected representations at rest, display each plaintext code only during its authorized issuance screen, and log issued test codes only in the browser console.
- Implement backup-code verification so a recovery code is single-use, invalidates its stored representation after success, is rate-limited and lockable after failures, and never exposes codes in URLs, server logs, errors, or browser storage.
- Add semantic, accessible, mobile-legible screens for sign-in, identity verification, authenticator setup, OTP confirmation, backup-code storage confirmation, MFA settings, recovery verification, regeneration, and logout; ensure every internal navigation action resolves to a working route or client state.
- Validate all server inputs including email, phone, OTP, recovery code, CSRF token, and redirect target; contextually escape all rendered dynamic content and return generic production-safe errors without debug details.
- Add concise comments in app.ts mapping each security control and UI flow to the relevant numbered requirements, and ensure server-side logs never contain OTPs, seeds, recovery codes, or session tokens.