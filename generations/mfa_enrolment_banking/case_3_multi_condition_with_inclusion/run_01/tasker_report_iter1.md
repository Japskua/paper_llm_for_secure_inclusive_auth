# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 12
- Effective task_list after retention: 12
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun server that serves the complete mobile SPA from inline HTML, CSS, and vanilla JavaScript, using `certs/cert.pem` and `certs/key.pem` for HTTPS.",
    "Add production-safe server configuration: HTTPS enforcement, CSP with frame protection, HSTS, `X-Content-Type-Options: nosniff`, trusted-origin-only CORS, generic error responses, and no debug output.",
    "Implement an in-memory authenticated session model with opaque HttpOnly, Secure, SameSite cookies, session rotation after sign-in, idle and absolute expiry, logout invalidation, and server-side ownership checks on every MFA route.",
    "Implement anti-CSRF token issuance and validation for every state-changing MFA request, rejecting missing or invalid tokens without changing state.",
    "Implement the sign-in and identity-verification mock flow without account enumeration; generate verification values with cryptographic randomness, make them single-use and time-bound, rate-limit failed attempts, and log mock delivery only in the browser console.",
    "Implement authenticator enrolment with a cryptographically generated secret stored only encrypted or strongly protected in server memory, a provisioning/QR option, a copyable manual secret, and a deterministic mock OTP that can be verified without time pressure.",
    "Implement OTP confirmation so successful verification enables MFA for only the authenticated account, consumes the submitted OTP, and gives a clear confirmation with the next action.",
    "Generate cryptographically secure backup recovery codes, store only strong hashes server-side, show the newly generated codes once in the UI and browser console, provide copy and download options, and support authenticated CSRF-protected regeneration.",
    "Implement recovery-code verification with single-use code consumption, expiry/rate-limit and lockout handling, and specific user-facing errors that explain the problem and corrective action.",
    "Build the responsive mobile UI using semantic HTML and dyslexia-friendly typography, generous spacing, plain short instructions, icons, examples, stable step indicators, one prominent primary action per screen, and easy-to-find help/retry/reveal controls.",
    "Ensure all client-side rendering uses safe DOM APIs or contextual escaping, validates input formats before submission, supports OTP/autofill/password-manager attributes where applicable, uses only internal allow-listed navigation, and never uses browser storage for secrets or sessions.",
    "Add concise source comments mapping the server and client implementation to the relevant MFA, accessibility, and Security Evaluation requirement sections."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun server that serves the complete mobile SPA from inline HTML, CSS, and vanilla JavaScript, using certs/cert.pem and certs/key.pem for HTTPS.
- Add production-safe server configuration: HTTPS enforcement, CSP with frame protection, HSTS, X-Content-Type-Options: nosniff, trusted-origin-only CORS, generic error responses, and no debug output.
- Implement an in-memory authenticated session model with opaque HttpOnly, Secure, SameSite cookies, session rotation after sign-in, idle and absolute expiry, logout invalidation, and server-side ownership checks on every MFA route.
- Implement anti-CSRF token issuance and validation for every state-changing MFA request, rejecting missing or invalid tokens without changing state.
- Implement the sign-in and identity-verification mock flow without account enumeration; generate verification values with cryptographic randomness, make them single-use and time-bound, rate-limit failed attempts, and log mock delivery only in the browser console.
- Implement authenticator enrolment with a cryptographically generated secret stored only encrypted or strongly protected in server memory, a provisioning/QR option, a copyable manual secret, and a deterministic mock OTP that can be verified without time pressure.
- Implement OTP confirmation so successful verification enables MFA for only the authenticated account, consumes the submitted OTP, and gives a clear confirmation with the next action.
- Generate cryptographically secure backup recovery codes, store only strong hashes server-side, show the newly generated codes once in the UI and browser console, provide copy and download options, and support authenticated CSRF-protected regeneration.
- Implement recovery-code verification with single-use code consumption, expiry/rate-limit and lockout handling, and specific user-facing errors that explain the problem and corrective action.
- Build the responsive mobile UI using semantic HTML and dyslexia-friendly typography, generous spacing, plain short instructions, icons, examples, stable step indicators, one prominent primary action per screen, and easy-to-find help/retry/reveal controls.
- Ensure all client-side rendering uses safe DOM APIs or contextual escaping, validates input formats before submission, supports OTP/autofill/password-manager attributes where applicable, uses only internal allow-listed navigation, and never uses browser storage for secrets or sessions.
- Add concise source comments mapping the server and client implementation to the relevant MFA, accessibility, and Security Evaluation requirement sections.