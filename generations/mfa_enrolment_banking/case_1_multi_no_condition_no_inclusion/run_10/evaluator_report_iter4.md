## SUMMARY

The artifact is a well-structured single-file Bun HTTPS MFA enrolment SPA with server-side session handling, CSRF validation, encrypted authenticator-secret storage, hashed recovery codes, rate limiting, and a mobile-friendly UI. However, it has a critical TOTP implementation defect that causes authenticator enrolment to fail for roughly half of generated OTP values. Its CSP also permits unrestricted inline script/style execution through `'unsafe-inline'`, which does not meet the stated secure-CSP requirement.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The HTML, CSS, browser JavaScript, API logic, and `Bun.serve` configuration are contained in `app.ts`. The only external files referenced are the required pre-provided TLS certificate files.

- **PASS — HTTPS/TLS is configured.**  
  `Bun.serve` uses `certs/cert.pem` and `certs/key.pem`. HSTS is also emitted in `baseHeaders()`.

- **PASS — Mobile-responsive, legible SPA UI is provided.**  
  The page includes a viewport meta tag, constrained mobile-width layout, usable input sizes, accessible labels, and responsive button/action wrapping.

- **PASS — Identity verification mock flow works and delivers the mock OTP to the browser console/UI logs.**  
  `/api/signin` generates a cryptographically random six-digit identity challenge, returns it only for the evaluation mock flow, and the browser logs it with `console.log`.

- **FAIL — Authenticator/TOTP verification is reliably functional.**  
  `totp()` constructs the OTP integer with JavaScript bitwise operators:
  ```ts
  const numeric = ((signature[offset] & 127) << 24) | ...
  ```
  JavaScript bitwise operations produce signed 32-bit integers. When bit 31 is set after the shift, `numeric` becomes negative. The returned OTP can therefore contain `-`, such as `-12345` or `00-123`, which fails `validOtp()` (`/^[0-9]{6}$/`) and makes authenticator enrolment impossible for those windows. This will occur for approximately half of HMAC outputs.

- **PASS — Manual authenticator setup is available.**  
  The UI shows both a manual setup secret and provisioning URI, and provides fields for manual secret confirmation and OTP entry.

- **PASS — Recovery codes are securely generated, displayed once, and can be regenerated after verification.**  
  Codes use CSPRNG output, are generated in a suitable recovery-code format, are stored only as peppered SHA-256 hashes, are displayed once via `pendingRecoveryDisplay`, and one code is consumed before regeneration is permitted.

- **PASS — MFA endpoint authorization and IDOR protection are substantially implemented.**  
  Authenticated MFA operations require a server-side session with `session.account`, and no user identifier supplied by the client controls access to another account’s MFA settings.

- **PASS — CSRF protection is applied to state-changing API requests.**  
  POST endpoints parse a JSON body and require a valid per-session CSRF token before state changes are processed. The session cookie is `SameSite=Strict`.

- **PASS — Session handling includes secure cookie attributes, rotation, expiry, and logout invalidation.**  
  Cookies include `HttpOnly`, `Secure`, `SameSite=Strict`, and `Max-Age`. Sessions have idle and absolute expiry checks. Session IDs are rotated after sign-in and identity verification, and logout deletes the server-side session and expires the cookie.

- **PASS — Rate limiting and temporary lockout are implemented.**  
  Identity, authenticator, and recovery verification attempts lock for ten minutes after five failed attempts.

- **PASS — OTP/recovery-code lifecycle protections are implemented.**  
  Identity codes are time-bound and single-use. Recovery codes are consumed on use. The authenticator confirmation code is only accepted once for enrolment.

- **PASS — Sensitive values are not placed in URLs, browser storage, non-HttpOnly cookies, or server logs.**  
  There is no `localStorage` or `sessionStorage` use. Session IDs are only held in HttpOnly cookies. Sensitive mock values are intentionally logged only in the browser console as explicitly required for evaluation.

- **PASS — Input validation and safe output rendering are implemented.**  
  Server-side validation is present for email, phone, OTP, secret, recovery code, CSRF token, and redirect values. Browser rendering uses `textContent` rather than unsafe HTML insertion.

- **PASS — Open redirects are prevented.**  
  `allowedRedirect()` restricts redirect values to a small allow-list of internal values.

- **FAIL — The CSP is not sufficiently secure.**  
  The server sends a CSP header, but it includes:
  ```http
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  ```
  Allowing `'unsafe-inline'` weakens CSP’s protection against injected script and style execution. Since this is a security-focused MFA enrolment application, the inline script and style should instead be authorized with a per-response nonce or fixed content hashes.

- **PASS — Other required security headers and restricted CORS are present.**  
  The application sets HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `Referrer-Policy`, and `Permissions-Policy`. CORS accepts only explicit localhost TLS origins.

- **PASS — Generic error responses are used.**  
  API failures return generic messages without stack traces or sensitive details.

## FAILING_ITEMS

- **Critical functional defect:** TOTP generation may return a negative/non-numeric OTP because signed JavaScript bitwise arithmetic is used to construct the dynamic-truncation integer. Such values are rejected by the OTP validator, preventing MFA authenticator confirmation for affected time windows.

- **Security misconfiguration:** The CSP allows unrestricted inline scripts and styles through `'unsafe-inline'`. This undermines the intended XSS mitigation of the CSP on a sensitive MFA enrolment page.

## NEW_TASKS

1. Fix `totp()` so the dynamically truncated HMAC value is calculated as an unsigned number without signed bitwise overflow. For example, replace the signed bitwise composition with arithmetic using `(signature[offset] & 0x7f) * 0x1000000` plus the remaining bytes, then ensure the result always produces exactly six decimal digits matching `/^[0-9]{6}$/`.

2. Replace CSP `'unsafe-inline'` directives with nonce- or hash-based authorization for the inline `<style>` and `<script>` blocks. Generate a cryptographically random nonce per HTML response, attach it to the style/script elements, and emit the same nonce in `style-src` and `script-src` CSP directives.

## DECISION

**FAIL**