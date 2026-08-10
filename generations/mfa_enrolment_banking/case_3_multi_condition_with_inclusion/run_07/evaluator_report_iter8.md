## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security controls, server-side session ownership checks, CSRF validation, encrypted TOTP secret storage, hashed recovery codes, rate limiting, and a generally accessible mobile UI. However, it does not fully meet the MFA provisioning and mock-code requirements: the displayed “QR code” is a decorative pseudo-random canvas rather than a scannable QR code, and re-requesting a practice code does not actually send the new code to the browser console as claimed. The default font choice also does not clearly satisfy the stated dyslexia-friendly typeface requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, external assets, or compilation**
  - All server, HTML, CSS, and browser JavaScript are contained in `app.ts`.
  - It uses `Bun.serve` directly and references only local TLS certificate files.

- **PASS — HTTPS/TLS server uses the required certificate locations**
  - Bun is configured with:
    - `certs/cert.pem`
    - `certs/key.pem`
  - The server is served through TLS rather than plain HTTP.

- **PASS — Mobile-responsive, semantic-enough SPA UI**
  - The document includes a viewport meta tag and responsive CSS.
  - The UI is constrained to a mobile-friendly content width and includes mobile font/layout adjustments.
  - It uses meaningful landmarks such as `main`, `header`, and `section`.

- **PARTIAL / FAIL — Dyslexia-inclusive typography**
  - Spacing, plain language, clear status messages, large controls, short instructions, and icons are generally good.
  - However, the declared primary font is `Arial,Verdana,sans-serif`, meaning Arial is normally selected first. Arial is not a specifically dyslexia-friendly typeface, and the artifact does not establish a clearly dyslexia-oriented font choice.
  - The requirement explicitly asks for a “clear, legible, dyslexia-friendly typeface.”

- **PASS — Clear step progression, plain-language guidance, retry support, and no visual clutter**
  - The flow has consistent numbered steps, prominent primary actions, concise help text, visible status/error feedback, and no animations or countdowns.
  - Inputs include examples for email, OTP, and recovery-code formats.
  - The UI supports copying setup details and backup codes.

- **FAIL — QR provisioning option is not functional**
  - `qr(value)` creates a pseudo-random canvas pattern based on a seed:
    ```js
    for(let y=0;y<n;y++)for(let x=0;x<n;x++){
      seed=(seed*1664525+1013904223)>>>0;
      if((seed>>>29)&1)ctx.fillRect(x*s,y*s,s,s)
    }
    ```
  - This does not encode the provisioning URI as a valid QR code and cannot be scanned by an authenticator app.
  - The UI explicitly instructs users to scan it, so this is a functional failure.
  - The manual key and copy options are present, but they do not make the offered QR option valid.

- **PASS — Manual authenticator provisioning is supported**
  - The setup response returns an `otpauth://` URI and a base32 manual secret.
  - The UI displays the manual key and provides copy buttons for both the URI and secret.
  - The server can validate real TOTP codes generated from that secret.

- **PARTIAL / FAIL — Practice-code re-request behavior is inaccurate and does not meet the browser-console mock requirement**
  - Initial practice-code reveal works:
    - The server returns the mock code.
    - The browser calls `console.log("Mock OTP for academic test:", r.code)`.
  - However, `/api/test/mock/rerequest` creates a new mock challenge but returns no code:
    ```ts
    return response({ ok: true, message: "A fresh practice code was sent to the browser console. The earlier one no longer works." });
    ```
  - The client only clears `mock` and displays that message:
    ```js
    if(r){mock="";note(r.message)}
    ```
  - No fresh code is logged to the browser console. The user must separately press “Send practice code to console.”
  - This makes the server message false and breaks the expected “re-request code” behavior.

- **PASS — OTP verification is simulated and functional**
  - Real TOTP verification is implemented with HMAC-SHA-1 and a standard six-digit TOTP calculation.
  - OTPs are time-bound and a TOTP counter step cannot be reused.
  - The mock OTP is deterministic per stored challenge and can be verified once.

- **PASS — Backup recovery-code generation and verification work**
  - Backup codes are generated using cryptographic random bytes.
  - Only hashes are retained server-side.
  - A successfully used recovery code is removed, making it single-use.
  - The UI supports copying, printing, hiding, replacing, and checking a backup code.

- **PASS — Server-side authorization and IDOR resistance**
  - Protected endpoints require a valid server-side session.
  - The session is associated with the fixed authenticated account, and the server does not accept client-controlled account/user/session identifiers.
  - Requests containing `accountId`, `userId`, or `sessionId` are rejected for protected state changes.

- **PASS — CSRF protection for authenticated state-changing routes**
  - Protected POST requests require both a matching `X-CSRF-Token` and a trusted same-origin HTTPS `Origin`.
  - Session cookies use `SameSite=Strict`.
  - The authentication route requires trusted origin validation before issuing a session.

- **PASS — Secure session-cookie and session lifecycle controls**
  - Cookies include `HttpOnly`, `Secure`, and `SameSite=Strict`.
  - Sessions have idle and absolute expiration checks.
  - Authentication invalidates an existing session before issuing a new one.
  - Logout invalidates the session and expires the cookie.

- **PASS — Security headers and restrictive browser policy**
  - Responses include CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store`.
  - No permissive CORS headers are emitted.

- **PASS — At-rest protection for TOTP secrets and recovery codes**
  - TOTP secrets are encrypted with AES-GCM using an in-memory cryptographic key.
  - Recovery codes are hashed with SHA-256 plus a random server-side pepper.
  - Cryptographically secure random generation is used for sessions, CSRF tokens, secrets, challenges, and recovery codes.

- **PASS — Input validation and output-encoding controls**
  - Email, phone, PIN, OTP, and recovery-code inputs are validated server-side.
  - Dynamic user-controlled visible values are escaped before HTML interpolation.
  - Client-visible logs use `textContent`.
  - No database or SQL query surface exists.

- **PASS — Failed-verification throttling / lockout**
  - Login and MFA verification attempts are rate-limited.
  - Five failures trigger a five-minute lockout.
  - Failure messaging is generic enough for login credentials and provides actionable code-entry guidance.

- **PASS — No browser persistence of secrets or session tokens**
  - The application does not use `localStorage`, `sessionStorage`, or non-HttpOnly cookies for secrets/session state.
  - Sensitive values are held only in memory during the page session.

## FAILING_ITEMS

- The QR canvas is not a real QR code. It is a decorative random pattern and cannot encode or be scanned as the offered `otpauth://` provisioning URI.
- The “Request a fresh practice code” action does not log or return the newly generated mock code. Its success message incorrectly says that the fresh code was sent to the browser console.
- The primary font selection is Arial before Verdana and does not clearly satisfy the explicit requirement for a dyslexia-friendly typeface.

## NEW_TASKS

1. Replace the pseudo-random `qr(value)` canvas implementation with a real, self-contained QR-code encoder that encodes the exact `otpauth://` URI and produces a scannable QR image without external assets or network calls.

2. Update `/api/test/mock/rerequest` to return the newly generated mock OTP, then update the browser handler to immediately call `console.log` with that returned code and retain it for “Use practice code.”

3. Update the CSS font stack so the primary rendered typeface is a clearly dyslexia-friendly, broadly available choice, with suitable fallback fonts; ensure it remains legible at mobile viewport sizes.

## DECISION

**FAIL**