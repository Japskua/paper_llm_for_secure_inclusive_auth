## SUMMARY

The artifact is a valid single-file Bun/TypeScript password-recovery SPA. It serves a nonce-protected HTML/CSS/vanilla-JS UI over TLS, implements a functional simulated recovery-code/manual-entry/MFA/password-update flow, and includes the required security controls such as per-session CSRF validation, token expiry/single use, throttling, Argon2id password hashing, restrictive headers, and output-safe DOM updates.

## FUNCTIONAL_CHECK

- **PASS — Single-file Bun application with no build tooling or external assets.**  
  The server, HTML template, CSS, and browser-side JavaScript are all contained in `app.ts`. It uses Bun directly and imports only built-in Node-compatible modules.

- **PASS — HTTPS/TLS is used with the required certificate locations.**  
  The server reads `certs/cert.pem` and `certs/key.pem` and starts `Bun.serve` with TLS. It does not offer a plaintext HTTP listener.

- **PASS — Security headers and CSP are configured.**  
  Responses include HSTS, CSP with per-response nonces, `X-Content-Type-Options`, frame protection, restrictive referrer/permissions policies, COOP, CORP, no-store caching, and a restrictive CSP including `form-action 'self'` and `frame-ancestors 'none'`.

- **PASS — CSRF protection is implemented for sensitive state-changing requests.**  
  Each session receives a cryptographically random CSRF token. All POST recovery endpoints require both a matching CSRF header and a same-origin `Origin` header.

- **PASS — Session protections are present.**  
  Session cookies are random and configured with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and a finite lifetime. Session-bound recovery authorization is checked before MFA and password update actions.

- **PASS — Account enumeration is mitigated.**  
  The reset-request endpoint returns the same generic confirmation message and response shape for valid, invalid, and unknown identifiers. The account identifier is not rendered to the browser UI or returned by API responses.

- **PASS — Recovery tokens are random, short-lived, hashed server-side, and single-use.**  
  Reset tokens are generated using cryptographic randomness, stored only as SHA-256 digests, expire after 15 minutes, and are consumed before a recovery authorization is issued.

- **PASS — Manual recovery-code entry and simulated recovery link both function.**  
  The reset token is returned for the academic mock flow, logged in the browser console/UI log, placed into a simulated reset-link URL, and can also be entered manually in the verification form.

- **PASS — MFA is implemented in the simulated flow.**  
  Recovery-code verification creates a short-lived authorization bound to the current session. MFA must complete before password updates are permitted. The deterministic test MFA value is logged in the browser as required for the simulated academic flow.

- **PASS — Brute-force throttling is implemented.**  
  Reset requests are throttled to three attempts per ten minutes per session. Recovery-code verification and MFA verification are each throttled to five attempts per ten minutes per session.

- **PASS — Strong password policy and secure password storage are implemented.**  
  Passwords must be 12–128 characters, contain uppercase, lowercase, numeric, and symbol characters, and contain no spaces. Passwords are stored with Bun’s Argon2id implementation and are not retained in plaintext.

- **PASS — XSS/injection protections are appropriately implemented for vanilla JavaScript.**  
  User-controlled values are not inserted through `innerHTML`; UI messages and log content use `textContent`/text nodes. Inputs are validated server-side, and the CSP only permits nonce-authorized script and style blocks.

- **PASS — UX and safety guidance are present.**  
  The UI provides clear status/error feedback, accessible live regions, visible password requirements, manual-code support, a success state, and explicit anti-phishing guidance stating that staff will not request passwords or verification codes.

- **PASS — No external network calls or broken internal navigation are present.**  
  Browser requests use only same-origin relative API paths. The simulated recovery link points to the same application and is handled through the `reset` query parameter.

## FAILING_ITEMS

- None identified.

## NEW_TASKS

1. No remediation tasks are required.

## DECISION

PASS