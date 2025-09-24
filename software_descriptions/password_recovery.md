# Password Recovery System — Requirements (Single-Page, Client-Only, Mocked)

Purpose
This document specifies a self-contained, single-HTML-file password recovery flow for an academic AI evaluation. All logic runs entirely in the browser (no backend). Recovery “delivery” and verification are simulated via console.log and deterministic mock values.
Note: This is not for production use.

⸻

1. Scope
   • Build a single HTML page that implements a realistic, end-to-end “Forgot password” flow.
   • Include all UI screens/states in this single file (can be shown/hidden via JavaScript).
   • Simulate sending and verifying recovery codes/tokens in the console, not via real email/SMS.
   • Use one hardcoded test account (see §6).
   • Allow a user to set a new password after a successful mock verification.
   • Provide a polished UI: clear labels, form validation, inline errors, disabled/enabled buttons appropriately, focus management between steps, and success/failure states.
   • Use vanilla HTML/CSS/JS (no build tools). Optional: include a single inline <style> and <script> in the HTML file.

Out of scope (explicitly exclude):
• Real user management, databases, or servers.
• Real email/SMS, cryptography, rate limiting, or persistent authentication.
• Multi-user flows or true session handling.

⸻

2. User Journey (Happy Path)
    1. User clicks “Forgot your password?” link/button on the page.
    2. Identify account screen is shown (username or email input).
    3. On submit:
       • If the identifier matches the hardcoded account, show Delivery method selection.
       • Log a mock recovery code + link to the console (see §7).
    4. User chooses Email (only option required) and continues.
    5. Enter code screen: user enters the code that was printed in the console.
    6. On successful code validation, show Set new password screen.
    7. User enters and confirms a new password (client-side rules in §8).
    8. Show Success screen; allow “Back to Sign in”.

Error paths are specified in §9.

⸻

3. Page Architecture
   • A single index.html containing:
   • Header with app name (“Password Recovery Demo”).
   • Main container holding 5 view states:
    1. Start (contains the “Forgot your password?” entry point and a mock sign-in form with disabled submit)
    2. Identify account
    3. Choose delivery method (only “Email” is required)
    4. Enter code
    5. Set new password
    6. Success
       • Footer with test/disclaimer text.
       • Each state is a <section> toggled by hidden attribute or display:none.
       • Navigation between states via buttons; Back buttons where meaningful (except to Start after success, which should go to Sign-in).

⸻

4. Visual/Interaction Requirements
   • Layout: responsive, centered card UI (max-width ~440px).
   • Controls: labeled inputs, 44px min tap targets, visible focus outlines.
   • Buttons: primary/secondary styles, disabled state when invalid.
   • Feedback: inline error text under fields; non-blocking toasts not required.
   • Loading: simple inline spinner or “Please wait…” text during “sending” (simulated delay 600–1200ms).
   • Focus management: move focus to the first interactive element when a new state is shown.
   • Keyboard support: Enter submits active form; Esc does nothing special.

⸻

5. States & Content

5.1 Start
• Elements:
• Mock sign-in form (Email, Password, disabled “Sign in”).
• Link/button: “Forgot your password?” → routes to Identify Account.
• Content notes: explain this is a demo; real sign-in disabled.

5.2 Identify Account
• Fields:
• Email or username (single text input).
• Buttons: Continue (disabled until non-empty), Back (to Start).
• Validation:
• Required; case-insensitive comparison allowed.
• On submit (valid and match):
• Simulate “lookup” delay.
• Transition to Delivery Method.
• Console: print mock code/link (see §7).
• On submit (no match): show inline error (“We couldn’t find that account.”).

5.3 Choose Delivery Method
• Options (radio list; only one required):
• Email: display masked email ja\*\*\*@example.com.
• Buttons: Send code (initially enabled), Back (to Identify).
• On Send code:
• Simulate sending delay.
• Show confirmation text “We’ve sent a code to your email (check console in this demo).”
• Auto-advance to Enter Code after 1–2s or require user to click Continue.

5.4 Enter Code
• Fields:
• 6-digit code text input (numeric only; allow pasting).
• Buttons: Verify (disabled until 6 digits), Resend code, Back (to Delivery).
• Behaviors:
• Verify: compare with mock code; success → Set New Password.
• Resend code: generate a new mock code (see §7), print to console, display small notice “New code sent. Use the latest one.”
• Limit of 3 failed attempts → show friendly lock message (“Too many attempts. Please resend a new code.”) and disable Verify until Resend.

5.5 Set New Password
• Fields:
• New password
• Confirm password
• Optional checkbox: “Show password”
• Buttons: Save password (disabled until valid), Back (to Enter Code).
• On success:
• Save to in-memory variable only (no storage required).
• Transition to Success.

5.6 Success
• Message: “Your password has been reset.”
• Button: Back to Sign in → Start state (clear transient UI state).

⸻

6. Hardcoded Test Account
   • Username: testuser
   • Email: jane.doe@example.com
   (Mask as ja\*\*\*@example.com in UI.)
   • Original password: arbitrary (unused).
   • New password: any string passing rules in §8; store in JS variable window.\_\_demoLastSetPassword for inspection.

⸻

7. Mock Delivery & Console Protocol

When an identifier is validated or when the user taps Resend code, log:

[RecoveryDemo] Delivering mock reset code via EMAIL to jane.doe@example.com
[RecoveryDemo] CODE: 493120
[RecoveryDemo] RESET LINK: https://example.com/reset?token=RESET-TOKEN-ABC123 (demo only)

Rules:
• CODE is a deterministic or pseudo-random 6-digit string. It must change on Resend.
• RESET LINK is static or includes the token above; clicking it does nothing (demo).
• Keep the latest code as the only valid one.

⸻

8. Password Rules (Client-Side)
   • Required length ≥ 10 characters.
   • Must include at least 3 of 4 classes: lowercase, uppercase, digit, symbol.
   • Must not contain the username or the local part of the email (case-insensitive).
   • Confirmation must exactly match.
   • Show an inline strength meter (very simple: Weak/Okay/Strong) and a checklist that turns green as rules are met.
   • Do not persist the password anywhere except the in-memory variable for demo.

Error messages (examples):
• “Password must be at least 10 characters.”
• “Add a number or symbol to make it stronger.”
• “Confirmation does not match.”

⸻

9. Error Handling & Edge Cases
   • Unknown account: Show inline error at Identify screen; allow re-entry.
   • Rate/attempts (mock): 3 wrong codes → lock Verify; nudge to Resend.
   • Expired code (mock): Codes “expire” after 5 minutes (client timer). Expired → show message, require Resend.
   • Empty/paste spaces: Trim inputs.
   • Connectivity: No network required; avoid network calls.
   • Refresh: A full page refresh resets the flow to Start.
   • Accessibility basics: Provide labels, aria-live for inline errors, and focus management when state changes.

⸻

10. Non-Functional Requirements
    • Performance: Initial page load ≤ 200KB total (HTML+CSS+JS).
    • Compatibility: Latest Chrome, Firefox, Safari, Edge. Mobile & desktop layouts.
    • Security disclaimer: All mechanisms are mock/demo; no real secrets; console logging is intentional for this study.
    • Maintainability: Clear function names, modular JS (e.g., RecoveryFlow, UI, MockDelivery), comments explaining each step.

⸻

11. Data Model (In-Memory Only)

{
user: {
username: "testuser",
email: "jane.doe@example.com"
},
state: {
currentView: "start" | "identify" | "delivery" | "code" | "setPassword" | "success",
latestCode: "493120",
latestCodeIssuedAt: 1710000000000,
failedCodeAttempts: 0,
newPasswordTemp: null
}
}

⸻

12. Events & Handlers
    • onClickForgot() → show Identify.
    • onSubmitIdentify(identifier) → validate vs hardcoded; on success call issueCode(); go Delivery.
    • onClickSendCode() → issueCode(); go Code or show “Code sent” then continue.
    • onSubmitCode(code) → verify vs state.latestCode, attempts++, success → Set Password.
    • onClickResend() → issueCode(); reset attempts; notify.
    • onSubmitNewPassword(pw1, pw2) → validate per §8; on success set window.\_\_demoLastSetPassword = pw1; go Success.
    • onClickBack(target) → navigate to previous state; clear transient errors.

issueCode():
• Generate 6-digit code (e.g., Math.floor(100000 + Math.random()\*900000)).
• Save to state; set timestamp; console.log per §7.

⸻

13. UI Copy (Minimum)
    • Start: “Forgot your password?”
    • Identify: “Enter your email or username.”
    • Delivery: “Choose how to receive your code.” (Email only in this demo)
    • Enter Code: “Enter the 6-digit code we sent to your email (check console in this demo).”
    • Set Password: “Create a new password.” + checklist.
    • Success: “Your password has been reset.”

⸻

14. Acceptance Criteria (Definition of Done)
    • Single index.html renders without errors and no external network calls.
    • Flow includes all states in §5 and transitions work as described.
    • Hardcoded account in §6 recognized; any other identifier rejected with inline error.
    • Sending/Resending logs to console exactly in the format of §7; latest code only is valid.
    • Code entry enforces 6 digits; wrong code attempts count and lock after 3 until Resend.
    • Code expires after ~5 minutes (client timer).
    • Password rules in §8 enforced with inline checklist and strength hint.
    • On success, window.\_\_demoLastSetPassword equals the new password; Success screen shown.
    • Buttons reflect disabled/enabled state based on validity; focus moves correctly on each screen change.
    • Works on desktop and mobile sizes; layout remains readable.
    • No libraries required; if used, must be embedded and not fetch externally.

⸻

15. Manual Test Script (for evaluators)
    1.  Load the page. Click Forgot your password?
    2.  Enter testuser → Continue. Observe console shows CODE + RESET LINK.
    3.  Choose Email → Send code. (Optional: see new console log if implemented here as well.)
    4.  Enter the logged 6-digit code → Verify.
    5.  Enter a weak password (e.g., abc) → see validation errors.
    6.  Enter a strong password and matching confirm → Save password.
    7.  See Success screen.
    8.  Repeat from step 2 with an unknown identifier and verify inline error.
    9.  Enter wrong codes 3× → Verify becomes locked; Resend generates a new code in console; old code becomes invalid.
    10. Wait >5 minutes (or mock the clock) → previously issued code should be rejected as expired.

⸻

16. (Optional) Inclusivity Add-On (use for “inclusive” cases)

If you need the inclusivity-enhanced requirements for your Case 3/4 runs, add:
• Provide keyboard-only usability (Tab order, Enter submits).
• Ensure screen reader labeling (aria-label, aria-live="polite" on error summaries).
• Avoid exclusive reliance on email: also offer “Backup code” option (still mocked in console).
• Copy in plain language, avoid jargon; provide brief “Why we ask this” hints near sensitive steps.
• Support low-bandwidth mode (no images/fonts required).

⸻

17. Deliverables
    • One file: index.html
    • Semantic HTML, inline CSS & JS
    • Commented sections mapping to this spec
    • No build step required

⸻

End of Requirements
