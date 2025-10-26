# Password Recovery System — Requirements

Purpose
This document specifies a password recovery flow for an academic AI evaluation. Create regular HTML, CSS, and JavaScript (no frameworks) Single-Page app to render the UI. The entire app — HTML template, inline JS logic, and Bun server — must exist in one file (app.ts). Bun serves the HTML and runs any JS logic directly (no bundlers, compilers, or external assets). Recovery “delivery” and verification are simulated via console.log and deterministic mock values, but the verifications must work. If there is a verification link, allow the code to be submited also manually. All internal links (e.g., to verification pages or confirmation screens) must function correctly. No external network calls. No build tools. You have Bun.sh version 1.3.0. Interactivity must work directly in the browser when the Bun server responds with the HTML+CSS+JS. There will be ready-made TLS certificates with mkcert, that point to "localhost 127.0.0.1 ::1". These will be later placed to folder "certs/cert.pem" and "certs/key.pem". Use them when creating the Bun server.

Use-case description:

Alex is a university student with dyslexia. Alex needs to submit an assignment before a deadline. When trying to access the school portal, the password has expired, so a new one must be created, in order for Alex to access the university portal.

Inclusivity requirements:
People with dyslexia can find it challenging to read dense text, process complex instructions, and remember or accurately type long strings like strong passwords. They may also experience stress and time pressure when working with systems that rely heavily on reading or typing accuracy. The login and submission process must therefore be clear, readable, and forgiving. Avoid long instructions, complex language, and unnecessary repetition of steps. Support users by reducing reading load and minimizing opportunities for error.
• Use clear, concise, and plain language in all instructions and messages.
• Present important information in short sentences or bullet points rather than long paragraphs.
• Provide clear visual structure with headings and spacing to make reading easier.
• Offer readable fonts and good contrast (avoid all caps, italics, or low-contrast colors).
• Give users the option to listen to text or copy instructions easily.
• Allow time flexibility and make sure timeouts or deadlines are clearly visible.
• Provide simple feedback when errors occur and guide the user step by step to fix them.
• Ensure navigation and naming are consistent so users can easily find the correct page or file upload location.

Overall, the system should reduce reading complexity, minimize error frustration, and give users confidence to complete tasks even under time pressure.

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
