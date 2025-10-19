SUMMARY:
The single-file Bun app provides a secure HTTPS server and a SPA that implements a clear password recovery flow with strong security controls (CSRF, HSTS/CSP, Argon2id hashing, rate limiting, MFA). It supports both verification link and manual code entry and logs demo tokens/codes to the browser console. However, progress persistence (pause and resume) is not implemented correctly, and the CSP currently conflicts with inline style attributes in the markup.

FUNCTIONAL_CHECK:
- Single-file app.ts with Bun HTTPS server using certs/cert.pem and certs/key.pem: PASS — Uses Bun.serve with TLS from the expected paths.
- SPA rendered with HTML+CSS+vanilla JS (no frameworks), interactivity works in browser directly: PASS — Inline JS with CSP nonce; client-side routing and forms work.
- Password recovery flow: request reset, verify by link or 6-digit code, set new password, then login + MFA to success: PASS — All steps present; API endpoints implemented and wired.
- Mock “delivery” via console.log in the browser; deterministic tokens/codes: PASS — /api/request-reset returns token/code/link and client logs them; MFA code logged on login.
- Manual code submission supported alongside link-based verification: PASS — /api/verify-token accepts token or 6-digit code.
- All internal links (including verification links) function: PASS — Hash-routing supports #/verify?token=..., Help, and step navigation.
- Inclusivity: simple step-by-step UI, clear feedback, visible progress, help easy to find, no time pressure: PASS — Progress bar, step headings, muted guidance, Help & Safety page; no timeouts.
- Inclusivity: user can pause and return without losing progress (resume last step): FAIL — session.lastView is never updated; no auto-resume based on session state (canSetPassword/mfaPending). Refresh returns to login, losing orientation.
- Security: CSRF tokens unique per session and validated on all sensitive POST routes: PASS — Session-scoped CSRF; validated on all /api POSTs.
- Security: Prevent user enumeration / exposure of identifiers: PASS — Generic responses; reset always returns demo info without revealing existence; no private identifiers shown.
- Security: Access control on sensitive routes (no IDOR): PASS — /api/set-password gated by session.canSetPassword + resetUserId from validated token.
- Security: XSS mitigations (sanitize input, escape outputs, no inline handlers, CSP with nonce): PASS — Server/client sanitization; textContent used for DOM updates; CSP nonce restricts scripts.
- Security: CSP, HSTS, and secure headers configured: FAIL — CSP forbids inline style attributes, but markup includes several style="" attributes; this will violate CSP and be blocked by modern browsers.
- Security: HTTPS enforced and secure cookies: PASS — Only HTTPS server provided; HSTS enabled; cookies Secure, HttpOnly, SameSite=Strict.
- Security: Password reset tokens random, single-use, short-lived: PASS — Random base64url, single-use flag, 15-minute expiry.
- Security: Passwords hashed with bcrypt/Argon2 (no plaintext): PASS — Argon2id via Bun.password.hash.
- Security: Brute force/guessing throttled: PASS — Per-session+IP+route rate limiting with exponential backoff.
- Security: MFA implemented: PASS — Login triggers MFA; code validated with 10-minute TTL.
- SSRF/open redirects prevention: PASS — No outgoing requests or redirects; generated link uses same origin with forced https.
- Deliverables: semantic HTML structure and comments mapping to requirements: PASS — Uses header/main/section/aside/footer; comments reference security requirements.

FAILING_ITEMS:
- Progress persistence is not functional:
  - session.lastView is never updated anywhere; it always remains "login".
  - On refresh, the app does not auto-route based on in-session state (e.g., canSetPassword or mfaPending), so users can lose orientation after pausing.
- CSP vs inline styles:
  - The CSP specifies style-src 'self' 'nonce-<...>' but the markup contains inline style attributes (e.g., style="justify-content: space-between;"). These will be blocked by CSP, causing violations and inconsistent styling.

NEW_TASKS:
1. Persist last view in session:
   - Add a small POST endpoint /api/last-view (CSRF-protected) that stores the provided view string into session.lastView after sanitization.
   - In the client, modify show(view) to POST to /api/last-view with { view } to keep the server-side last step up to date.
2. Auto-resume based on session state:
   - Server: On GET "/", set the initial view priority in renderHTML to reflect session state:
     - If session.canSetPassword => data-last="setPassword"
     - Else if session.mfaPending => data-last="mfa"
     - Else use session.lastView or "login"
   - Client: Keep current logic reading meta data-last to set window.location.hash on first load.
3. Optional robustness for resume (minimal, if not doing #1): Embed additional meta flags in renderHTML (e.g., data-can-set-password, data-mfa-pending) and, on initial route, prefer setPassword/mfa routes accordingly. This avoids adding a new endpoint but still restores context after refresh.
4. Fix CSP/style conflicts:
   - Remove inline style="" attributes in markup and move those rules into the existing nonced <style> block (e.g., define utility classes like .justify-between, .mt-16, .container to replace inline styles).
   - Keep CSP as-is (style-src 'self' 'nonce-...') to avoid weakening it. Do not add 'unsafe-inline'.

DECISION:
FAIL