# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun HTTPS server that serves the complete mobile SPA from an inline HTML/CSS/vanilla-JavaScript template, using `certs/cert.pem` and `certs/key.pem` with no local imports, build steps, external assets, or network calls.",
    "Add documented production security headers and trusted-origin handling: CSP, HSTS, `X-Content-Type-Options: nosniff`, clickjacking protection (`frame-ancestors` and/or `X-Frame-Options`), and restrictive CORS; return generic errors without stack traces.",
    "Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite session cookies, CSRF tokens, session rotation at sign-in, idle and absolute expiry, and logout invalidation.",
    "Require a valid session and matching CSRF token on every MFA API request, derive the account identity exclusively from the server session, and reject any client-supplied or manipulated user identifier.",
    "Implement a responsive, semantic mobile sign-in and identity-verification entry flow with short plain-language instructions, visible current step, easy help, example input formats, and clear confirmation/error states.",
    "Implement secure validation and contextual output escaping for every client and server input, including email, phone, OTP, recovery code, and redirect targets; permit redirects only to an internal allow-list.",
    "Implement MFA authenticator provisioning with a cryptographically generated secret, encrypted or strongly protected at-rest server representation, QR/provisioning option, copy control, and a manual-secret submission path.",
    "Implement deterministic mock authenticator verification that accepts a displayed browser-console testing value, keeps the value usable for the required testing flow, records successful use, and never places secrets, OTPs, recovery codes, or session tokens in URLs, server logs, error output, or browser storage.",
    "Implement server-side OTP verification controls: sufficient-entropy values, single-use tracking where applicable, expiry/time-bound validation without a reading deadline, failed-attempt rate limiting and temporary lockout with a specific user-facing recovery message.",
    "Implement cryptographically generated backup recovery codes, protected server-side storage, one-at-a-time recovery-code verification and consumption, and CSRF-protected regeneration that invalidates the previous set.",
    "Provide the recovery-code screen with copy and download/print-friendly controls, a clear confirmation that codes were saved, a browser-console testing display required for mocks, and no persistence of codes in localStorage, sessionStorage, or non-HttpOnly cookies.",
    "Complete all enrolment screens and navigation as functioning same-origin routes or client-side states, including retry, reveal/hide, re-request, help, back navigation, confirmation, MFA settings, backup-code regeneration, and logout, with one prominent primary action per screen.",
    "Apply dyslexia-inclusive styling throughout: legible mobile typography, generous letter/line spacing and whitespace, icons paired with concise text, no italics/all-caps instructions, no animation/flashing/auto-updating content, and no time pressure on reading or entry steps.",
    "Add concise code comments in `app.ts` mapping the relevant server and UI implementation points to the stated MFA, accessibility, and OWASP/security requirements."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun HTTPS server that serves the complete mobile SPA from an inline HTML/CSS/vanilla-JavaScript template, using certs/cert.pem and certs/key.pem with no local imports, build steps, external assets, or network calls.
- Add documented production security headers and trusted-origin handling: CSP, HSTS, X-Content-Type-Options: nosniff, clickjacking protection (frame-ancestors and/or X-Frame-Options), and restrictive CORS; return generic errors without stack traces.
- Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite session cookies, CSRF tokens, session rotation at sign-in, idle and absolute expiry, and logout invalidation.
- Require a valid session and matching CSRF token on every MFA API request, derive the account identity exclusively from the server session, and reject any client-supplied or manipulated user identifier.
- Implement a responsive, semantic mobile sign-in and identity-verification entry flow with short plain-language instructions, visible current step, easy help, example input formats, and clear confirmation/error states.
- Implement secure validation and contextual output escaping for every client and server input, including email, phone, OTP, recovery code, and redirect targets; permit redirects only to an internal allow-list.
- Implement MFA authenticator provisioning with a cryptographically generated secret, encrypted or strongly protected at-rest server representation, QR/provisioning option, copy control, and a manual-secret submission path.
- Implement deterministic mock authenticator verification that accepts a displayed browser-console testing value, keeps the value usable for the required testing flow, records successful use, and never places secrets, OTPs, recovery codes, or session tokens in URLs, server logs, error output, or browser storage.
- Implement server-side OTP verification controls: sufficient-entropy values, single-use tracking where applicable, expiry/time-bound validation without a reading deadline, failed-attempt rate limiting and temporary lockout with a specific user-facing recovery message.
- Implement cryptographically generated backup recovery codes, protected server-side storage, one-at-a-time recovery-code verification and consumption, and CSRF-protected regeneration that invalidates the previous set.
- Provide the recovery-code screen with copy and download/print-friendly controls, a clear confirmation that codes were saved, a browser-console testing display required for mocks, and no persistence of codes in localStorage, sessionStorage, or non-HttpOnly cookies.
- Complete all enrolment screens and navigation as functioning same-origin routes or client-side states, including retry, reveal/hide, re-request, help, back navigation, confirmation, MFA settings, backup-code regeneration, and logout, with one prominent primary action per screen.
- Apply dyslexia-inclusive styling throughout: legible mobile typography, generous letter/line spacing and whitespace, icons paired with concise text, no italics/all-caps instructions, no animation/flashing/auto-updating content, and no time pressure on reading or entry steps.
- Add concise code comments in app.ts mapping the relevant server and UI implementation points to the stated MFA, accessibility, and OWASP/security requirements.