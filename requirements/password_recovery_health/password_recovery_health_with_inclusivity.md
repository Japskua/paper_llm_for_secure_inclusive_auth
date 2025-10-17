# Password Recovery System — Requirements (Single-Page, Client-Only, Mocked)

Purpose
This document specifies a self-contained, single-HTML-file password recovery flow for an academic AI evaluation. All logic runs entirely in the browser (no backend). Recovery “delivery” and verification are simulated via console.log and deterministic mock values.
Note: This is not for production use.

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

Deliverables
• One file: index.html
• Semantic HTML, inline CSS & JS
• Commented sections mapping to this spec
• No build step required

End of Requirements
