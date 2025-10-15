# Password Recovery System — Requirements (Single-Page, Client-Only, Mocked)

Purpose
This document specifies a self-contained, single-HTML-file password recovery flow for an academic AI evaluation. All logic runs entirely in the browser (no backend). Recovery “delivery” and verification are simulated via console.log and deterministic mock values.
Note: This is not for production use.

User story:
As a patient, I want to log in to my hospital account to review and confirm updates to my privacy settings, so that I can book a follow-up appointment for my medication review.

User profile:
Sam, 67 years old, has chronic heart disease and ADHD. Sam occasionally struggles with remembering passwords and maintaining focus during long online procedures.

Context:
Sam uses the hospital’s online portal to manage appointments and view health information. Due to policy updates, Sam must log in and accept new privacy terms before hospital staff can book an appointment.

Problem or barrier:
Sam has forgotten the account password. The password reset process contains several detailed steps and complex password requirements, which are hard to complete due to attention difficulties and cognitive fatigue.

Acceptance criteria:
• Sam can reset the password successfully.
• The interface supports users who may lose focus or need simpler instructions.
• Sam can access the account and accept the privacy update to proceed with the appointment.

Deliverables
• One file: index.html
• Semantic HTML, inline CSS & JS
• Commented sections mapping to this spec
• No build step required

End of Requirements
