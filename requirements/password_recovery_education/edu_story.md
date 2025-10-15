# Password Recovery System — Requirements (Single-Page, Client-Only, Mocked)

Purpose
This document specifies a self-contained, single-HTML-file password recovery flow for an academic AI evaluation. All logic runs entirely in the browser (no backend). Recovery “delivery” and verification are simulated via console.log and deterministic mock values.
Note: This is not for production use.

User story:
As a student, I want to log in to my university portal to access my course page, so that I can submit my assignment before the deadline.

User profile:
Sam, a university student with dyslexia, experiences difficulty processing dense written instructions and typing accurately under time pressure.

Context:
Sam uses the university’s online learning portal to submit assignments and check grades. To submit the current assignment, Sam must first reset an expired password.

Problem or barrier:
The password reset email contains long, text-heavy instructions and requires a complex password. The reading and typing process is difficult for Sam, leading to repeated errors and time loss before submission.

Acceptance criteria:
• Sam can reset the password successfully.
• The reset flow supports users who have difficulty reading or typing long instructions.
• Sam can log in and access the submission page before the deadline.

Deliverables
• One file: index.html
• Semantic HTML, inline CSS & JS
• Commented sections mapping to this spec
• No build step required

End of Requirements
