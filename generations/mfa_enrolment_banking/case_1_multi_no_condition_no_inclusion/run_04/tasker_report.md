# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete mobile SPA, and contains no local-module imports, build steps, frameworks, external assets, or external network calls.",
    "Add production-safe server error handling and restrictive security headers on every response: CSP, HSTS, `X-Content-Type-Options: nosniff`, clickjacking protection, and CORS restricted to the HTTPS localhost origin.",
    "Implement secure HttpOnly, Secure, SameSite session cookies with server-side session records, session rotation after authentication, idle and absolute expiry, and logout invalidation.",
    "Implement a mocked sign-in and identity-verification flow that uses generic responses to avoid account enumeration and does not place account identifiers, session tokens, or verification values in URLs or browser storage.",
    "Require a valid server-side authenticated session for every MFA route and derive the account identity exclusively from that session, rejecting supplied, manipulated, or guessed user identifiers.",
    "Issue and validate an anti-CSRF token for every state-changing MFA request, including enrolment confirmation, MFA verification, backup-code use, regeneration, and logout.",
    "Implement server-side validation for all submitted email, phone, OTP, recovery-code, and redirect inputs; escape all dynamic HTML output; and allow redirects only to an explicit internal-path allow-list.",
    "Implement MFA authenticator provisioning with a cryptographically generated shared secret, encrypted or strongly protected server-side storage, and a manual secret-entry path alongside the displayed provisioning information.",
    "Implement deterministic mock authenticator verification that accepts the documented test code, is time-bound and single-use, tracks failed attempts server-side, and temporarily locks verification after repeated failures.",
    "Return mocked provisioning and verification values only through the intended simulated browser flow and log the test values with `console.log` in the browser, without server logging of OTPs, secrets, backup codes, or session tokens.",
    "Generate recovery codes with a cryptographically secure RNG, store only strong hashes server-side, display newly generated codes once in the protected UI, and support single-use recovery-code verification.",
    "Add a protected backup-code regeneration flow that requires CSRF validation and MFA/recovery verification, invalidates the prior code set, and applies rate limiting and lockout behavior.",
    "Build the responsive, semantic mobile HTML/CSS/vanilla-JS SPA screens for sign-in, identity verification, authenticator setup, OTP confirmation, backup-code storage, MFA settings, regeneration, and logout, with all navigation paths handled by `app.ts`.",
    "Add concise code comments in `app.ts` mapping each authentication, authorization, cryptography, validation, header, and UI control to the corresponding numbered security requirement."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete mobile SPA, and contains no local-module imports, build steps, frameworks, external assets, or external network calls.
- Add production-safe server error handling and restrictive security headers on every response: CSP, HSTS, X-Content-Type-Options: nosniff, clickjacking protection, and CORS restricted to the HTTPS localhost origin.
- Implement secure HttpOnly, Secure, SameSite session cookies with server-side session records, session rotation after authentication, idle and absolute expiry, and logout invalidation.
- Implement a mocked sign-in and identity-verification flow that uses generic responses to avoid account enumeration and does not place account identifiers, session tokens, or verification values in URLs or browser storage.
- Require a valid server-side authenticated session for every MFA route and derive the account identity exclusively from that session, rejecting supplied, manipulated, or guessed user identifiers.
- Issue and validate an anti-CSRF token for every state-changing MFA request, including enrolment confirmation, MFA verification, backup-code use, regeneration, and logout.
- Implement server-side validation for all submitted email, phone, OTP, recovery-code, and redirect inputs; escape all dynamic HTML output; and allow redirects only to an explicit internal-path allow-list.
- Implement MFA authenticator provisioning with a cryptographically generated shared secret, encrypted or strongly protected server-side storage, and a manual secret-entry path alongside the displayed provisioning information.
- Implement deterministic mock authenticator verification that accepts the documented test code, is time-bound and single-use, tracks failed attempts server-side, and temporarily locks verification after repeated failures.
- Return mocked provisioning and verification values only through the intended simulated browser flow and log the test values with console.log in the browser, without server logging of OTPs, secrets, backup codes, or session tokens.
- Generate recovery codes with a cryptographically secure RNG, store only strong hashes server-side, display newly generated codes once in the protected UI, and support single-use recovery-code verification.
- Add a protected backup-code regeneration flow that requires CSRF validation and MFA/recovery verification, invalidates the prior code set, and applies rate limiting and lockout behavior.
- Build the responsive, semantic mobile HTML/CSS/vanilla-JS SPA screens for sign-in, identity verification, authenticator setup, OTP confirmation, backup-code storage, MFA settings, regeneration, and logout, with all navigation paths handled by app.ts.
- Add concise code comments in app.ts mapping each authentication, authorization, cryptography, validation, header, and UI control to the corresponding numbered security requirement.