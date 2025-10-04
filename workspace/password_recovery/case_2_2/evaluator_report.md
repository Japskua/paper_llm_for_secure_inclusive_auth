SUMMARY
The provided single-file Password Recovery Demo implements the complete, client-only “Forgot password” flow per the specification. It includes all required screens, polished UI behavior, mocked delivery via console logs, validation, error handling, delays, focus management, and in-memory state. The hardcoded account is recognized, codes are generated/logged correctly, attempts and expiry are enforced, and password rules with checklist and strength indicator are implemented. No external calls are made, and the UI is responsive.

FUNCTIONAL_CHECK
- Single index.html renders without errors and no external network calls: PASS — One HTML file with inline CSS/JS; no external resources or network calls.
- Flow includes all states in §5 and transitions work as described: PASS — Start, Identify, Delivery, Enter Code, Set New Password, Success all present with working navigation and back buttons; success returns to Start.
- Hardcoded account in §6 recognized; any other identifier rejected with inline error: PASS — Case-insensitive match against “testuser” or “jane.doe@example.com”; others show inline “We couldn’t find that account.”.
- Sending/Resending logs to console exactly in the format of §7; latest code only is valid: PASS — Logs three lines exactly as specified; latestCode updated on issue/resend; only latest code is accepted.
- Code entry enforces 6 digits; wrong code attempts count and lock after 3 until Resend: PASS — Input constrained to digits, maxlength 6; Verify disabled until 6 digits; after 3 failures, Verify disabled and lock message shown; Resend resets attempts/lock.
- Code expires after ~5 minutes (client timer): PASS — Verification checks now() - latestCodeIssuedAt > 5 minutes, then disables Verify and requires Resend.
- Password rules in §8 enforced with inline checklist and strength hint: PASS — Length ≥10, 3/4 classes, excludes username/local-part, and exact match enforced; checklist turns green per rule; Weak/Okay/Strong pill updates.
- On success, window.__demoLastSetPassword equals the new password; Success screen shown: PASS — Value assigned on submit; Success view displayed.
- Buttons reflect disabled/enabled state based on validity; focus moves correctly on each screen change: PASS — Buttons toggle disabled appropriately; focus moves to first enabled control when views change.
- Works on desktop and mobile sizes; layout remains readable: PASS — Centered responsive card (max-width 440px), adequate spacing and touch targets; no layout breakpoints required.
- No libraries required; if used, must be embedded and not fetch externally: PASS — Vanilla JS/HTML/CSS only.

FAILING_ITEMS
- None observed.

NEW_TASKS
- None.

DECISION
PASS