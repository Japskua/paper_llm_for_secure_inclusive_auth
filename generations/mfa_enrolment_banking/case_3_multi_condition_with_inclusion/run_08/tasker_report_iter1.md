# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 16
- Effective task_list after retention: 16
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` that starts a Bun HTTPS server using `certs/cert.pem` and `certs/key.pem`, serves the complete inline HTML/CSS/vanilla-JS SPA, and has no local imports, build step, external assets, or network calls.",
    "Add server-wide production security handling: HTTPS-only requests, restricted same-origin CORS, CSP with frame-ancestors, HSTS, X-Content-Type-Options, clickjacking protection, and generic non-verbose error responses.",
    "Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite cookies, session rotation after authentication, idle and absolute expiry, and logout invalidation.",
    "Require the authenticated session on every MFA API route and derive the account identity only from the session; reject supplied, guessed, or manipulated user identifiers.",
    "Implement per-session anti-CSRF token issuance and validation for every state-changing MFA request, including authenticator confirmation, recovery-code regeneration, and logout.",
    "Implement a mobile-responsive, semantic enrolment UI with a dyslexia-friendly system typeface, generous spacing, plain short instructions, icons paired with text, no motion, clear current-step indication, and one visually prominent primary action per screen.",
    "Implement the sign-in and identity-verification screens with accessible labels, example input formats, browser autofill attributes, brief help, retry controls, and neutral errors that do not reveal whether an account exists.",
    "Validate all client and server inputs for expected format and length, escape all dynamic output before rendering, and permit navigation redirects only to an allow-list of internal SPA routes.",
    "Generate each OTP challenge with cryptographically secure randomness, store only protected verification material server-side, make successful OTPs single-use, enforce generous but defined validity, and return test mock values only to browser-side `console.log` without logging secrets on the server.",
    "Add failed-verification rate limiting and temporary lockout for OTP and recovery-code attempts, with specific UI errors explaining the problem and the next corrective action.",
    "Implement authenticator provisioning with a securely generated secret protected at rest, a scannable locally generated QR representation, a copy action, and a manually usable setup secret/code so long values never require transcription.",
    "Implement authenticator confirmation that accepts the deterministic mock OTP, confirms success plainly, supports retry and code re-request without penalty, and never stores secrets, OTPs, or tokens in browser storage.",
    "Generate recovery codes with a cryptographically secure RNG, store only protected versions at rest, present copy and download/print-friendly options, show the mock codes in browser `console.log` for evaluation, and allow each recovery code to be used once.",
    "Implement authenticated MFA settings routes to view enrolment status, use a recovery code, and regenerate recovery codes, enforcing account ownership, CSRF validation, protected storage, and rate limits on each route.",
    "Add concise code comments in `app.ts` that map the server and UI controls to the relevant MFA, accessibility, and Security Evaluation requirements.",
    "Verify every visible internal link, form, back/retry action, help control, logout control, and confirmation route works within the single-page flow at mobile viewport widths."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts that starts a Bun HTTPS server using certs/cert.pem and certs/key.pem, serves the complete inline HTML/CSS/vanilla-JS SPA, and has no local imports, build step, external assets, or network calls.
- Add server-wide production security handling: HTTPS-only requests, restricted same-origin CORS, CSP with frame-ancestors, HSTS, X-Content-Type-Options, clickjacking protection, and generic non-verbose error responses.
- Implement an in-memory authenticated-session model with cryptographically random HttpOnly, Secure, SameSite cookies, session rotation after authentication, idle and absolute expiry, and logout invalidation.
- Require the authenticated session on every MFA API route and derive the account identity only from the session; reject supplied, guessed, or manipulated user identifiers.
- Implement per-session anti-CSRF token issuance and validation for every state-changing MFA request, including authenticator confirmation, recovery-code regeneration, and logout.
- Implement a mobile-responsive, semantic enrolment UI with a dyslexia-friendly system typeface, generous spacing, plain short instructions, icons paired with text, no motion, clear current-step indication, and one visually prominent primary action per screen.
- Implement the sign-in and identity-verification screens with accessible labels, example input formats, browser autofill attributes, brief help, retry controls, and neutral errors that do not reveal whether an account exists.
- Validate all client and server inputs for expected format and length, escape all dynamic output before rendering, and permit navigation redirects only to an allow-list of internal SPA routes.
- Generate each OTP challenge with cryptographically secure randomness, store only protected verification material server-side, make successful OTPs single-use, enforce generous but defined validity, and return test mock values only to browser-side console.log without logging secrets on the server.
- Add failed-verification rate limiting and temporary lockout for OTP and recovery-code attempts, with specific UI errors explaining the problem and the next corrective action.
- Implement authenticator provisioning with a securely generated secret protected at rest, a scannable locally generated QR representation, a copy action, and a manually usable setup secret/code so long values never require transcription.
- Implement authenticator confirmation that accepts the deterministic mock OTP, confirms success plainly, supports retry and code re-request without penalty, and never stores secrets, OTPs, or tokens in browser storage.
- Generate recovery codes with a cryptographically secure RNG, store only protected versions at rest, present copy and download/print-friendly options, show the mock codes in browser console.log for evaluation, and allow each recovery code to be used once.
- Implement authenticated MFA settings routes to view enrolment status, use a recovery code, and regenerate recovery codes, enforcing account ownership, CSRF validation, protected storage, and rate limits on each route.
- Add concise code comments in app.ts that map the server and UI controls to the relevant MFA, accessibility, and Security Evaluation requirements.
- Verify every visible internal link, form, back/retry action, help control, logout control, and confirmation route works within the single-page flow at mobile viewport widths.