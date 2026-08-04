# TASKER REPORT — Iteration 1 · Step 1

## SUMMARY
- Raw tasks from Tasker: 15
- Effective task_list after retention: 15
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Create a single runnable `app.ts` Bun application that serves the complete HTML, CSS, and vanilla browser JavaScript inline, with no local modules, build steps, frameworks, external assets, or network calls.",
    "Configure the Bun server to use `certs/cert.pem` and `certs/key.pem` for HTTPS, redirect or reject insecure HTTP requests, and send HSTS, restrictive CSP, anti-clickjacking, MIME-sniffing, referrer, and cache-control security headers.",
    "Implement a semantic single-page password-recovery interface with functional in-app routes or state transitions for start recovery, token/code verification, password reset, sign-in confirmation, privacy-condition acceptance, and appointment-booking confirmation.",
    "Add an anti-phishing safety notice in the recovery UI stating that the hospital never requests passwords by email or support contact and that users should verify the localhost hospital address before entering credentials.",
    "Implement recovery initiation using a non-identifying account input response that does not reveal whether an account exists, does not expose usernames or patient data, and logs simulated delivery only in the browser console.",
    "Generate reset tokens with cryptographically secure randomness, associate each token only with the current simulated recovery session, enforce a short expiry and single use, and allow the delivered token to be submitted manually.",
    "Create a per-session CSRF token using secure randomness, deliver it only to the same browser session, and require valid CSRF validation for recovery initiation, token verification, password change, privacy acceptance, and appointment actions.",
    "Use secure session handling so sensitive server actions require the owning authenticated session and never accept user, patient, appointment, or reset-record identifiers supplied by the client as authorization.",
    "Implement deterministic simulated MFA after reset-token verification, log its delivery value in the browser console, accept the displayed code for testing without expiry, and throttle repeated invalid MFA submissions.",
    "Enforce password reset rules requiring a strong new password, confirmation match, and rejection of weak or common passwords; hash the accepted password with Bun-supported bcrypt or Argon2 functionality and never store or display plaintext passwords.",
    "Throttle recovery, reset-token, MFA, and sign-in verification failures by session or account context, provide safe generic feedback, and temporarily block further attempts after the configured failure threshold.",
    "Ensure all client-rendered dynamic values are inserted as text rather than HTML, validate inputs with strict allowlists and length limits, and prevent user-controlled URLs, redirects, scripts, event handlers, or markup from being executed.",
    "Restrict internal navigation and any post-action destination to an explicit in-app allowlist, with no arbitrary return URL, remote URL, open redirect, staff impersonation flow, or outbound request capability.",
    "Keep simulated patient, account, token, session, and appointment state only in server memory; return only the minimum status needed by the browser and never expose private identifiers, debug details, directory listings, or stack traces.",
    "Add clear source comments in `app.ts` mapping the relevant server and client controls to Security Requirements 1 through 5 and the single-file, mock-console, HTTPS, and routing deliverables."
  ]
}
```

## PARSED_TASKS
- Create a single runnable app.ts Bun application that serves the complete HTML, CSS, and vanilla browser JavaScript inline, with no local modules, build steps, frameworks, external assets, or network calls.
- Configure the Bun server to use certs/cert.pem and certs/key.pem for HTTPS, redirect or reject insecure HTTP requests, and send HSTS, restrictive CSP, anti-clickjacking, MIME-sniffing, referrer, and cache-control security headers.
- Implement a semantic single-page password-recovery interface with functional in-app routes or state transitions for start recovery, token/code verification, password reset, sign-in confirmation, privacy-condition acceptance, and appointment-booking confirmation.
- Add an anti-phishing safety notice in the recovery UI stating that the hospital never requests passwords by email or support contact and that users should verify the localhost hospital address before entering credentials.
- Implement recovery initiation using a non-identifying account input response that does not reveal whether an account exists, does not expose usernames or patient data, and logs simulated delivery only in the browser console.
- Generate reset tokens with cryptographically secure randomness, associate each token only with the current simulated recovery session, enforce a short expiry and single use, and allow the delivered token to be submitted manually.
- Create a per-session CSRF token using secure randomness, deliver it only to the same browser session, and require valid CSRF validation for recovery initiation, token verification, password change, privacy acceptance, and appointment actions.
- Use secure session handling so sensitive server actions require the owning authenticated session and never accept user, patient, appointment, or reset-record identifiers supplied by the client as authorization.
- Implement deterministic simulated MFA after reset-token verification, log its delivery value in the browser console, accept the displayed code for testing without expiry, and throttle repeated invalid MFA submissions.
- Enforce password reset rules requiring a strong new password, confirmation match, and rejection of weak or common passwords; hash the accepted password with Bun-supported bcrypt or Argon2 functionality and never store or display plaintext passwords.
- Throttle recovery, reset-token, MFA, and sign-in verification failures by session or account context, provide safe generic feedback, and temporarily block further attempts after the configured failure threshold.
- Ensure all client-rendered dynamic values are inserted as text rather than HTML, validate inputs with strict allowlists and length limits, and prevent user-controlled URLs, redirects, scripts, event handlers, or markup from being executed.
- Restrict internal navigation and any post-action destination to an explicit in-app allowlist, with no arbitrary return URL, remote URL, open redirect, staff impersonation flow, or outbound request capability.
- Keep simulated patient, account, token, session, and appointment state only in server memory; return only the minimum status needed by the browser and never expose private identifiers, debug details, directory listings, or stack traces.
- Add clear source comments in app.ts mapping the relevant server and client controls to Security Requirements 1 through 5 and the single-file, mock-console, HTTPS, and routing deliverables.