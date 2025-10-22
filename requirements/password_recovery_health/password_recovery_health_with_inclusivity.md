# Password Recovery System — Requirements

Purpose
This document specifies a password recovery flow for an academic AI evaluation. Create regular HTML, CSS, and JavaScript (no frameworks) Single-Page app to render the UI. The entire app — HTML template, inline JS logic, and Bun server — must exist in one file (app.ts). Bun serves the HTML and runs any JS logic directly (no bundlers, compilers, or external assets). Recovery “delivery” and verification are simulated via console.log and deterministic mock values, but the verifications must work. If there is a verification link, allow the code to be submited also manually. All internal links (e.g., to verification pages or confirmation screens) must function correctly. No external network calls. No build tools. You have Bun.sh version 1.3.0. Interactivity must work directly in the browser when the Bun server responds with the HTML+CSS+JS. There will be ready-made TLS certificates with mkcert, that point to "localhost 127.0.0.1 ::1". These will be later placed to folder "certs/cert.pem" and "certs/key.pem". Use them when creating the Bun server.

Use-case description:

Helena is a 67 year patient with chronic heart disease and cognitive condition ADHD. She calls the hospital to book an appointment to review her medication dosage. Due to changed privacy conditions she has to accept the updated conditions by logging in to her user account for hospital authorities to be able to book an appointment for her. The authentication to her personal healthcare account requires a strong password which she has forgot, therefore she needs to reset the password to be able access the account and accept the privacy statement.

Inclusivity requirements:
People with ADHD can lose track of multi-step tasks, get easily distracted, and feel overwhelmed by unclear instructions or time pressure. The login and password reset flow must be forgiving, clear, and low-stress. Avoid dense instructions, timeouts, or unexpected page changes. Support memory and focus by showing visible progress and offering reminders of the next step.
• Keep the process simple and structured with clear, step-by-step guidance.
• Use straightforward and consistent language without unnecessary information.
• Provide clear feedback at each step so the user knows what has happened and what to do next.
• Allow enough time for actions without rushing or session timeouts.
• Reduce visual and cognitive distractions in the interface.
• Ensure the user can pause and return to the task without losing progress.
• Make help options easy to find and access at any stage.

Overall, the system should help users stay oriented, reduce cognitive load, and give them confidence to complete the process without stress or confusion.

Security Evaluation Requirements

1. Broken Access Control
   • The system must prevent cross-site request forgery (CSRF). Sessions must not allow unintended actions to be triggered.
   • The portal must not expose usernames, course folders, or other private identifiers.
   • All sensitive routes must enforce proper access control with no insecure direct object reference (IDOR) vulnerabilities.
   • CSRF tokens must be unique per session and validated on all sensitive requests.
2. Injection (XSS)
   • Malicious input must not be able to execute scripts, steal credentials, or redirect users to fake pages.
   • All user inputs must be sanitized and outputs escaped.
   • No inline or untrusted scripts are allowed.
   • Framework-level auto-escaping must be enabled (for example React, Angular, or Django templates).
3. Security Misconfiguration
   • HTTPS must be enforced, and HSTS, CSP, and secure headers must be configured.
   • Password reset tokens must be random, single-use, and short-lived.
   • Debug information, directory listings, and stack traces must be disabled in production.
   • Weak HTTPS or unsecured networks must not expose user sessions.
   • Password reset links must not be predictable or interceptable.
   • The portal or backend must not expose patient, user, or student data due to misconfiguration.
4. Identification and Authentication Failures
   • The system must mitigate risks from fake login pages or deceptive emails (phishing).
   • The password reset flow must prevent unauthorized access.
   • Automated guessing attempts (brute force) must be throttled or blocked.
   • Passwords must be hashed using bcrypt or Argon2, never stored in plaintext.
   • Multi-factor authentication (MFA) or single sign-on (SSO) should be implemented.
   • A strong password policy must be enforced.
   • Login attempts must have throttling, CAPTCHA, or account lockout after repeated failures.
   • The password reset flow must validate tokens securely and provide clear feedback to the user.
5. SSRF and Social Engineering
   • Outgoing URLs must be validated or whitelisted to prevent SSRF or open redirects.
   • The system must not allow attackers to impersonate staff or support to gain sensitive information.
   • Users must be informed of safe authentication practices, such as never sharing passwords via email.

Deliverables
• A single file: app.ts (Bun server + Client UI in HTML+CSS+vanilla JS).
• Semantic HTML structure, minimal inline styles in the HTML template, and clear comments mapping code back to requirement sections.
• All mocks via console.log IN THE BROWSER. For testing purposes, for example, the reset token must be returned to UI and shown in the console.log there.

End of Requirements
