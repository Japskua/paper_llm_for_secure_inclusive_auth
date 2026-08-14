## SUMMARY

The artifact is a single-file Bun HTTPS SPA with substantial security and accessibility work: server-side session checks, CSRF checks, secure cookie flags, CSP/HSTS headers, validation, rate limiting, responsive UI, copy controls, and browser-console simulation values are implemented. However, it does not fully meet the functional and inclusivity requirements because its QR code generator produces an invalid Version 10 QR matrix, and the simulated authenticator-code step cannot re-request a fresh code after the displayed code expires. Therefore, the artifact should not be accepted as-is.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no frameworks, bundlers, compilation, or external assets.**  
  The server, HTML, CSS, and browser JavaScript are all embedded in `app.ts`. It uses `Bun.serve` directly and does not import external packages or make external network requests.

- **PASS — HTTPS/TLS configuration is present.**  
  `Bun.serve` is configured with `certs/cert.pem` and `certs/key.pem`, as required.

- **PASS — Responsive, mobile-oriented, dyslexia-conscious UI.**  
  The app uses a narrow mobile shell, readable Verdana/Arial typography, increased letter spacing and line height, generous control sizing, plain language, visible progress, examples for expected inputs, no moving/flashing UI, and clear status/error messages.

- **PASS — Sign-in, identity verification, authenticator setup, confirmation, recovery-code creation, completion, replacement, redemption, and logout flows are implemented.**  
  The SPA routes users through the expected stages and has working server endpoints for each stage.

- **PASS — Authentication and access control are enforced server-side.**  
  MFA endpoints use `requireSession`, do not accept user IDs, bind sessions to the fixed account owner, and use server-maintained stages. This prevents direct user-ID manipulation/IDOR in the provided implementation.

- **PASS — CSRF protection is implemented for state-changing actions.**  
  State-changing endpoints require an `X-CSRF-Token` matching the server-side session token, and requests are also origin-checked. The sign-in request uses a SameSite CSRF bootstrap cookie.

- **PASS — Secure response headers and restrictive CORS behavior are implemented.**  
  The app sets CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, Referrer-Policy, and Permissions-Policy. It does not emit permissive CORS headers and checks the trusted origin.

- **PASS — Session security measures are mostly implemented.**  
  Session IDs are cryptographically random, session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`, and idle/absolute timeout checks plus logout invalidation are implemented.

- **PASS — Input validation and output handling are implemented.**  
  Email, password, OTP, and recovery-code formats are validated server-side. Client rendering uses DOM APIs and `textContent`, avoiding direct injection of untrusted HTML.

- **PASS — OTP and recovery verification controls exist.**  
  Identity codes are time-bound and single-use; TOTP verification prevents reuse of accepted time counters; recovery codes are consumed after successful redemption. Failed attempts are rate-limited/locked across sign-in, identity, TOTP, and recovery flows.

- **PASS — Manual authenticator setup option is present.**  
  The setup screen displays a selectable secret, provides a copy button, exposes the provisioning URI on demand, and accepts manual six-digit authenticator-code entry.

- **FAIL — The offered QR code is not reliably valid/scannable.**  
  `qrSvg()` creates a Version 10 QR matrix (`n=57`) but does not reserve or write the mandatory Version Information fields required for QR Versions 7 through 40. Those matrix cells are instead filled as data modules. As a result, the generated SVG does not conform to the Version 10 QR format and may not scan correctly. This violates the requirement that the offered QR-code provisioning path work.

- **FAIL — The simulated authenticator confirmation code cannot be re-requested after it expires.**  
  `/api/authenticator/confirm` returns a simulated TOTP only when the user first presses “I added it to my app.” The confirmation screen has no “get another code,” “retry setup,” or equivalent action. Once the displayed TOTP ages beyond the accepted window, a user relying on the academic simulation cannot obtain a new valid code without using an external authenticator or restarting/resetting the flow. This conflicts with the requirement to let users retry and re-request codes without penalty and to allow generous time for code entry.

## FAILING_ITEMS

- The local QR encoder generates a Version 10 QR code without the required Version Information bits/reserved regions. The QR provisioning option is therefore non-compliant and not dependable.
- The authenticator confirmation screen lacks a way to obtain a fresh simulated TOTP or safely return to setup after the one-time displayed TOTP expires. This can make the simulated verification path fail for users who take their time.

## NEW_TASKS

1. Replace or correct `qrSvg()` so it generates standards-compliant, scannable QR codes for the provisioning URI, including correct Version 10 Version Information placement/reservation, error-correction data, masking, and format/version bits.
2. Add a CSRF-protected authenticator-code refresh/retry endpoint available during the `confirm` stage; in academic mode it must return a newly current simulated TOTP for browser-console logging.
3. Add a visible confirmation-screen action such as “Get a new test code” and/or “Back to authenticator setup,” with plain-language guidance that retrying is safe and does not penalize the user.

## DECISION

FAIL