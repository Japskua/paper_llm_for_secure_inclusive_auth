SUMMARY:
The provided index.html implements a complete, client-only, single-file password recovery demo with strong accessibility and mocked behaviors. It follows the requirements closely, includes explicit spec-mapping comments, and meets all acceptance criteria, including deterministic code generation, validation, live announcements, focus management, and robust restart behavior.

FUNCTIONAL_CHECK:
- 1. Single file: PASS — All HTML, CSS, and JS are inline in index.html; no build step.
- 2. Client-only: PASS — No fetch/XHR/import or external network calls; all logic runs in-browser.
- 3. Use-case fit: PASS — Short, clear steps with minimal text and high-contrast UI, plus features to aid dyslexia (show password, explicit rules, concise errors).
- 4. Semantic structure: PASS — Proper use of header, main, footer, section, form, label, button.
- 5. Four steps, single visibility: PASS — Steps for Request, Verify, Set Password, Success exist; only one .step.active is shown; aria-hidden managed.
- 6. Deterministic code: PASS — 6-digit code derived via djb2 hash of email; stored in state/sessionStorage.
- 7. Mock delivery: PASS — Code is output via console.log on request; not sent anywhere.
- 8. No password persistence; clear on success: PASS — Password validated client-side; not stored/sent; password inputs cleared on success.
- 9. Validation messages with role="alert": PASS — Email, code format/mismatch, and password rules errors shown in elements with role="alert" and aria-live.
- 10. Password rules enforced: PASS — Min 8 chars, at least one letter and one number; confirmation must match; enforced in JS.
- 11. Accessibility announcements: PASS — Polite aria-live region (#globalStatus with role="status") announces step/status messages.
- 12. Keyboard/focus: PASS — Active step heading gets focus on change; :focus-visible high-contrast outline defined; first input focused after brief delay.
- 13. Visibility toggles: PASS — Show/Hide buttons toggle input type, update button text, aria-pressed, and aria-label accordingly.
- 14. Restart behavior: PASS — All “Start over” buttons call startOver(); clear state/sessionStorage, reset forms, return to Step 1.
- 15. Utility class: PASS — .visually-hidden implemented with standard screen-reader-only technique (clip and clip-path).
- 16. Hidden helper: PASS — #restartHelp exists, visually hidden, referenced by #restartBtn via aria-describedby.
- 17. Robust aria-describedby: PASS — If #restartHelp missing, code removes aria-describedby from #restartBtn at runtime.
- 18. Spec mapping comments: PASS — Inline comments clearly map implementation to requirements/criteria.
- 19. Demo notice: PASS — UI text indicates demo nature (“No server”, “Mock”, “Console”) in header, steps, and footer.

FAILING_ITEMS:
- None.

NEW_TASKS:
- None.

DECISION:
PASS