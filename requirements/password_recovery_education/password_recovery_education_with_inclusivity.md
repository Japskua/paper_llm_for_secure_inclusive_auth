# Password Recovery System — Requirements (Single-Page, Client-Only, Mocked)

Purpose
This document specifies a self-contained, single-HTML-file password recovery flow for an academic AI evaluation. All logic runs entirely in the browser (no backend). Recovery “delivery” and verification are simulated via console.log and deterministic mock values.
Note: This is not for production use.

Use-case description:

Alex is a university student with dyslexia. He needs to hand in his assignment before midnight. When he tries to log into the school portal, his password has expired, so he must make a new one. The reset email has long instructions and asks for a strong password, which is hard for him to read and follow quickly. He makes mistakes typing the new password and has to try again. After logging in, Alex still needs to find the right course page and upload the correct file before the deadline.

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

Deliverables
• One file: index.html
• Semantic HTML, inline CSS & JS
• Commented sections mapping to this spec
• No build step required

End of Requirements
