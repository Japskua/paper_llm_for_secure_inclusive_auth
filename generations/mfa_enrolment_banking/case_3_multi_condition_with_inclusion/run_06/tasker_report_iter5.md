# TASKER REPORT — Iteration 5 · Step 13

## SUMMARY
- Raw tasks from Tasker: 6
- Effective task_list after retention: 6
- Note: Evaluator decides termination; Tasker.done is ignored.

## RAW_OUTPUT
```
{"task_list":["Replace automatic owner-session creation at GET / with a server-side authenticated-session mechanism; only issue an MFA session after authenticated ownership of Marcus’s account has been established. If an academic fixture is required, make it explicitly test-only and not automatically granted to every visitor.","On successful /api/identity/verify, invalidate the current session and create a new session ID with the same authorized account context and verified-identity state; send the replacement Secure/HttpOnly/SameSite cookie in the response.","Implement a usable simulated identity delivery mechanism for the academic flow that returns the mock code to the UI and logs it with console.log in the browser, without logging secrets on the server.","Define and implement deterministic academic mock values for identity verification, authenticator verification, and recovery-code testing, or provide a clearly isolated test mode that is enabled for the delivered academic artifact and consistently exposes those values in the browser UI and console.","Replace the pseudo-random SVG generator with a valid QR-code encoder for the otpauth:// provisioning URI, implemented inline without external assets or network calls. Retain the copyable manual Base32 secret option.","Change the repurposed provisioning button handler from by(\"make\").onclick = otp to a wrapper such as by(\"make\").onclick = () => otp() so that no click event is rendered as an error message."]}
```

## PARSED_TASKS
- Replace automatic owner-session creation at GET / with a server-side authenticated-session mechanism; only issue an MFA session after authenticated ownership of Marcus’s account has been established. If an academic fixture is required, make it explicitly test-only and not automatically granted to every visitor.
- On successful /api/identity/verify, invalidate the current session and create a new session ID with the same authorized account context and verified-identity state; send the replacement Secure/HttpOnly/SameSite cookie in the response.
- Implement a usable simulated identity delivery mechanism for the academic flow that returns the mock code to the UI and logs it with console.log in the browser, without logging secrets on the server.
- Define and implement deterministic academic mock values for identity verification, authenticator verification, and recovery-code testing, or provide a clearly isolated test mode that is enabled for the delivered academic artifact and consistently exposes those values in the browser UI and console.
- Replace the pseudo-random SVG generator with a valid QR-code encoder for the otpauth:// provisioning URI, implemented inline without external assets or network calls. Retain the copyable manual Base32 secret option.
- Change the repurposed provisioning button handler from by("make").onclick = otp to a wrapper such as by("make").onclick = () => otp() so that no click event is rendered as an error message.