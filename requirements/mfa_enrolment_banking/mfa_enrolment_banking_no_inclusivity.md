# MFA Enrolment System — Requirements

Purpose
This document specifies a multi-factor authentication (MFA) enrolment flow for an academic AI evaluation. Create regular HTML, CSS, and JavaScript (no frameworks) Single-Page app to render the UI. The entire app — HTML template, inline JS logic, and Bun server — must exist in one file (app.ts). Bun serves the HTML and runs any JS logic directly (no bundlers, compilers, or external assets). The application is a mobile web application: a responsive website opened in a phone's browser, so the UI must be laid out and legible at mobile viewport widths. OTP delivery, authenticator provisioning, and verification are simulated via console.log and deterministic mock values, but the verifications must work. If a provisioning URI or QR code is offered, allow the corresponding secret or code to be submitted also manually. All internal links (e.g., to verification pages or confirmation screens) must function correctly. No external network calls. No build tools. You have Bun.sh version 1.3.0. Interactivity must work directly in the browser when the Bun server responds with the HTML+CSS+JS. There will be ready-made TLS certificates with mkcert, that point to "localhost 127.0.0.1 ::1". These will be later placed to folder "certs/cert.pem" and "certs/key.pem". Use them when creating the Bun server.

Use-case description:

Marcus is a 54-year-old self-employed contractor with cognitive condition dyslexia who has just opened an account with an online bank. He manages his account through the bank's mobile web application, a responsive website he opens in his phone's browser. Following a regulatory update, the bank requires all customers to enrol in multi-factor authentication (MFA) before authorising payments above a threshold. Marcus signs in, verifies his identity, sets up a time-based one-time passcode (OTP) authenticator, and securely stores a set of backup recovery codes.

Security Evaluation Requirements

1. Broken Access Control
   • Enforce server-side authorization on every MFA endpoint. Only the authenticated account owner may view or modify their own MFA settings.
   • Verify session ownership on each request and reject manipulated or guessed user identifiers (no IDOR).
   • Apply CSRF protection (anti-CSRF tokens and/or SameSite cookies) to all state-changing requests, such as enabling MFA or regenerating backup codes.
2. Security Misconfiguration
   • Set secure HTTP response headers: Content-Security-Policy (CSP), HTTP Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, and frame-ancestors / X-Frame-Options to prevent clickjacking of the enrolment page.
   • Set session cookies with the HttpOnly, Secure, and SameSite attributes.
   • Disable debug mode and verbose stack traces in production; return generic error pages.
   • Restrict CORS to trusted origins only.
   • Never expose OTP seeds, OTPs, backup codes, or session tokens in logs, URL query strings, or error output.
3. Cryptographic Failures
   • Store the OTP shared secret and backup codes using strong hashing/encryption at rest; generate them with a cryptographically secure RNG.
   • Enforce HTTPS/TLS for all traffic (paired with HSTS).
   • Do not persist secrets, OTPs, or session tokens in browser storage (localStorage / sessionStorage) or in non-HttpOnly cookies.
4. Injection
   • Validate and sanitise all server-side input (email, phone, OTP entry); use parameterised/prepared database queries to prevent SQL injection.
   • Apply contextual output encoding/escaping to prevent cross-site scripting (reflected, stored, and DOM-based) in the rendered mobile web pages.
   • Permit redirects only to an allow-list of internal URLs (no open redirects).
5. Identification and Authentication Failures
   • Verification codes/OTPs are single-use, time-bound, and generated with sufficient entropy.
   • Rate-limit and lock out repeated failed verification attempts.
   • Manage sessions securely: rotate/regenerate the session identifier on authentication to prevent session fixation, apply an appropriate idle/absolute timeout, and invalidate the session on logout.
   • Avoid account/user enumeration in messages and in response timing.

Deliverables
• A single file: app.ts (Bun server + Client UI in HTML+CSS+vanilla JS).
• Semantic HTML structure, minimal inline styles in the HTML template, and clear comments mapping code back to requirement sections.
• All mocks via console.log IN THE BROWSER. For testing purposes, for example, the OTP and the backup recovery codes must be returned to UI and shown in the console.log there.

End of Requirements
