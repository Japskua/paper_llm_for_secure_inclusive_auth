# TASKER REPORT — Iteration 3 · Step 7

## SUMMARY
- Raw tasks from Tasker: 9
- Effective task_list after retention: 9
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{
  "task_list": [
    "Replace the TypeScript-only cast in client JS with plain JS (e.g., if (loginMfaCode && loginMfaCode.focus) loginMfaCode.focus()) so the SPA runs without syntax errors.",
    "Make /api/reset/request return identical JSON shape and log messages (including a reset link and 6‑digit code) whether or not the email exists.",
    "Generate indistinguishable decoy reset tokens for non-existent emails that pass verify and MFA steps but do not modify any account at password update.",
    "Ensure the password update endpoint returns a generic success for both real and decoy tokens without revealing account existence.",
    "Add a fixed artificial delay to /api/reset/request so response timing is uniform regardless of account existence.",
    "Restrict MFA short codes to numeric-only (0–9) with exactly 6 digits and apply this consistently in both login and reset flows.",
    "Align MFA input fields and copy with numeric codes (pattern for 6 digits, inputmode=numeric, placeholder 'Enter 6-digit code').",
    "Verify that both verification methods work after changes: manual 6-digit code entry and link-based token parsing from the URL.",
    "Re-run CSRF validation on all affected endpoints to confirm tokens are still required and verified after the changes."
  ]
}
```

## PARSED_TASKS
- Replace the TypeScript-only cast in client JS with plain JS (e.g., if (loginMfaCode && loginMfaCode.focus) loginMfaCode.focus()) so the SPA runs without syntax errors.
- Make /api/reset/request return identical JSON shape and log messages (including a reset link and 6‑digit code) whether or not the email exists.
- Generate indistinguishable decoy reset tokens for non-existent emails that pass verify and MFA steps but do not modify any account at password update.
- Ensure the password update endpoint returns a generic success for both real and decoy tokens without revealing account existence.
- Add a fixed artificial delay to /api/reset/request so response timing is uniform regardless of account existence.
- Restrict MFA short codes to numeric-only (0–9) with exactly 6 digits and apply this consistently in both login and reset flows.
- Align MFA input fields and copy with numeric codes (pattern for 6 digits, inputmode=numeric, placeholder 'Enter 6-digit code').
- Verify that both verification methods work after changes: manual 6-digit code entry and link-based token parsing from the URL.
- Re-run CSRF validation on all affected endpoints to confirm tokens are still required and verified after the changes.