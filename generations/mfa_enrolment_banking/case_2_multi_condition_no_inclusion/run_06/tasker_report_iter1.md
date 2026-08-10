# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 14
- Effective task_list after retention: 14
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete responsive SPA from inline HTML/CSS/vanilla JavaScript, and requires no local imports, build step, or external asset.",
    "Implement secure server response handling with trusted-origin-only CORS, CSP including `frame-ancestors`, HSTS, `X-Content-Type-Options: nosniff`, clickjacking protection, generic production errors, and comments mapping these controls to Security Requirement 2.",
    "Implement in-memory authenticated session management with cryptographically random session IDs, HttpOnly/Secure/SameSite cookies, session rotation on authentication, idle and absolute expiry, logout invalidation, and no session values exposed to client JavaScript, URLs, or logs.",
    "Implement server-side route authorization for every MFA read or mutation endpoint, deriving the account solely from the authenticated session and rejecting absent, expired, manipulated, or guessed account identifiers.",
    "Implement CSRF protection for every state-changing MFA request, validate the token server-side, and ensure the client sends it without placing it in URL query strings.",
    "Create the mobile-accessible sign-in and identity-verification flow with semantic HTML, clear dyslexia-friendly visual hierarchy, responsive phone-width layout, generic non-enumerating feedback, and working internal navigation.",
    "Implement validated server-side MFA enrolment input handling for email, phone, and OTP values; escape all dynamic rendered values; reject unsafe redirect targets except an explicit internal route allow-list; and document the injection/XSS protections in code comments.",
    "Implement authenticator provisioning with a cryptographically generated secret, encrypted or strongly protected in-memory-at-rest representation, a manually submittable provisioning secret/code, and browser-console-only mock delivery logging that never logs server secrets.",
    "Implement deterministic, time-bound, single-use authenticator OTP verification with cryptographically strong code generation where applicable, successful MFA activation, and browser console logging of test-only mock codes without URL, server-log, or persistent-browser-storage exposure.",
    "Implement failed-verification rate limiting and temporary lockout for authenticator and recovery-code verification attempts, returning generic user-facing failure messages.",
    "Generate cryptographically random backup recovery codes after successful MFA verification, store only strong hashes/protected values, display the plaintext codes only in the authenticated confirmation UI and browser console for the mock flow, and support single-use recovery-code verification.",
    "Implement authenticated backup-code regeneration protected by authorization, CSRF validation, session checks, and rate limiting; invalidate prior recovery codes and show the newly generated codes through the secure confirmation flow.",
    "Ensure all SPA routes, forms, back navigation, logout, authenticator verification, manual provisioning, recovery-code verification, and confirmation screens resolve through implemented `app.ts` handlers with no dead links or remote network requests.",
    "Add concise code comments throughout `app.ts` explicitly mapping the implemented controls to Requirements 1 through 5 and the single-file/mobile/mock-delivery constraints."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete responsive SPA from inline HTML/CSS/vanilla JavaScript, and requires no local imports, build step, or external asset.
- Implement secure server response handling with trusted-origin-only CORS, CSP including frame-ancestors, HSTS, X-Content-Type-Options: nosniff, clickjacking protection, generic production errors, and comments mapping these controls to Security Requirement 2.
- Implement in-memory authenticated session management with cryptographically random session IDs, HttpOnly/Secure/SameSite cookies, session rotation on authentication, idle and absolute expiry, logout invalidation, and no session values exposed to client JavaScript, URLs, or logs.
- Implement server-side route authorization for every MFA read or mutation endpoint, deriving the account solely from the authenticated session and rejecting absent, expired, manipulated, or guessed account identifiers.
- Implement CSRF protection for every state-changing MFA request, validate the token server-side, and ensure the client sends it without placing it in URL query strings.
- Create the mobile-accessible sign-in and identity-verification flow with semantic HTML, clear dyslexia-friendly visual hierarchy, responsive phone-width layout, generic non-enumerating feedback, and working internal navigation.
- Implement validated server-side MFA enrolment input handling for email, phone, and OTP values; escape all dynamic rendered values; reject unsafe redirect targets except an explicit internal route allow-list; and document the injection/XSS protections in code comments.
- Implement authenticator provisioning with a cryptographically generated secret, encrypted or strongly protected in-memory-at-rest representation, a manually submittable provisioning secret/code, and browser-console-only mock delivery logging that never logs server secrets.
- Implement deterministic, time-bound, single-use authenticator OTP verification with cryptographically strong code generation where applicable, successful MFA activation, and browser console logging of test-only mock codes without URL, server-log, or persistent-browser-storage exposure.
- Implement failed-verification rate limiting and temporary lockout for authenticator and recovery-code verification attempts, returning generic user-facing failure messages.
- Generate cryptographically random backup recovery codes after successful MFA verification, store only strong hashes/protected values, display the plaintext codes only in the authenticated confirmation UI and browser console for the mock flow, and support single-use recovery-code verification.
- Implement authenticated backup-code regeneration protected by authorization, CSRF validation, session checks, and rate limiting; invalidate prior recovery codes and show the newly generated codes through the secure confirmation flow.
- Ensure all SPA routes, forms, back navigation, logout, authenticator verification, manual provisioning, recovery-code verification, and confirmation screens resolve through implemented app.ts handlers with no dead links or remote network requests.
- Add concise code comments throughout app.ts explicitly mapping the implemented controls to Requirements 1 through 5 and the single-file/mobile/mock-delivery constraints.