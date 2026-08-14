# TASKER REPORT — Iteration 2 · Step 4

## SUMMARY
- Raw tasks from Tasker: 5
- Effective task_list after retention: 5
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace the decorative QR grid with a valid locally generated QR code encoding the issued standards-compliant `otpauth://totp/` URI, including URL-encoded issuer/account label, Base32 secret, algorithm, digits, and period.","In `/api/mfa/verify`, securely compare the submitted manual setup secret with the secret issued for the authenticated session and reject a mismatch with a clear retry message.","Track failed recovery-code verification attempts per authenticated session or account, rate-limit or lock access after the defined threshold, and reset the counter after a successful recovery-code verification.","Store recovery-code verification values using a hardened scheme with per-code salt and sufficient work factor, or a server-peppered keyed construction with adequate recovery-code entropy; do not retain direct unsalted SHA-256 hashes.","Resolve the conflicting mock-delivery and no-sensitive-logs requirements: remove sensitive values from the visible in-page log panel, and either remove them from browser logs or explicitly confine browser-console disclosure to the required test-only mock channel without server logging or URL/error exposure."]}
```

## PARSED_TASKS
- Replace the decorative QR grid with a valid locally generated QR code encoding the issued standards-compliant otpauth://totp/ URI, including URL-encoded issuer/account label, Base32 secret, algorithm, digits, and period.
- In /api/mfa/verify, securely compare the submitted manual setup secret with the secret issued for the authenticated session and reject a mismatch with a clear retry message.
- Track failed recovery-code verification attempts per authenticated session or account, rate-limit or lock access after the defined threshold, and reset the counter after a successful recovery-code verification.
- Store recovery-code verification values using a hardened scheme with per-code salt and sufficient work factor, or a server-peppered keyed construction with adequate recovery-code entropy; do not retain direct unsalted SHA-256 hashes.
- Resolve the conflicting mock-delivery and no-sensitive-logs requirements: remove sensitive values from the visible in-page log panel, and either remove them from browser logs or explicitly confine browser-console disclosure to the required test-only mock channel without server logging or URL/error exposure.