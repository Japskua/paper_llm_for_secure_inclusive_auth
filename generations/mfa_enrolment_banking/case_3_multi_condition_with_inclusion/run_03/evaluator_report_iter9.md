## SUMMARY

The artifact is a single-file Bun/TypeScript SPA with substantial MFA functionality, TLS setup, secure headers, session ownership checks, CSRF protection, encrypted TOTP seeds, hashed recovery codes, expiry, and rate limiting. However, it does not fully meet the requirements because the generated QR code contains incorrect format metadata and may not scan correctly, recovery-code verification is broken due to the request body being read twice, public hard-coded credentials undermine authentication security, and several dyslexia/inclusivity UX requirements are incomplete.

## FUNCTIONAL_CHECK

- **Single `app.ts` Bun server with inline HTML, CSS, and vanilla browser JavaScript: PASS**
  - The server, HTML template, inline CSS, and client-side JavaScript are all in the provided `app.ts`.
  - No framework, bundler, compiler, external asset, or network call is used.

- **TLS server using provided mkcert certificate paths: PASS**
  - `readFileSync("certs/cert.pem")` and `readFileSync("certs/key.pem")` are used in `Bun.serve({ tls: { cert, key } })`.

- **Mobile-responsive and readable UI: PASS**
  - The page includes the mobile viewport meta tag, a constrained mobile layout, adequate default font size, line height, spacing, prominent actions, and responsive QR sizing.

- **Dyslexia-friendly, low-reading-load UX: FAIL**
  - The UI uses generally plain language and spacing, but it does not provide easy-to-find help/hints on every step.
  - Sensitive values such as provisioning data and recovery codes cannot be hidden and revealed again.
  - The recovery-code regeneration confirmation is lost immediately because `message(...)` is called before `render()`, and `render()` clears `#msg`.
  - The recovery screen presents an immediate expiry-sensitive code-saving process without explaining that recovery codes expire after 24 hours.

- **Identity verification mock flow works: PASS**
  - The server creates a time-bound, single-use identity code.
  - In academic mode, the deterministic mock code is returned to the browser and logged through browser `console.log`.
  - The UI supports requesting a replacement code and supports `autocomplete="one-time-code"`.

- **Authenticator provisioning and manual setup support: FAIL**
  - The provisioning URI and manual secret are returned to the browser, shown in copyable controls, and the mock TOTP is logged in browser console.
  - However, the custom QR implementation writes the wrong QR format information. It encodes format data for a different error-correction/mask combination than the actual generated QR data/mask. This can cause authenticator apps to reject or incorrectly decode the QR code.
  - Specifically, the code uses `1 << 10` for format data even though the QR data is generated as Version 8-L with mask 0. The correct format data must represent L / mask 0, i.e. `8 << 10`.

- **Authenticator verification works with expiry, single-use protection, and rate limiting: PASS**
  - TOTP values are checked against a small clock-skew window.
  - Accepted time steps are stored in `user.used`, preventing reuse.
  - Invalid attempts are rate-limited and lock out after five failures.
  - The authenticator seed is encrypted at rest using AES-GCM.

- **Recovery-code generation, display, copy, regeneration, and acknowledgement: PARTIAL / FAIL**
  - Recovery codes are generated, stored as hashes, displayed to the user, copyable, logged in browser console in academic mock mode, and invalidated when regenerated.
  - However, the “new recovery codes were made” confirmation is not visible due to the render-clearing bug.
  - Recovery codes expire after 24 hours, but this deadline is not communicated to the user.
  - The recovery verification endpoint is broken and therefore recovery-code verification does not work.

- **Recovery-code verification works: FAIL**
  - `/api/recovery/verify` calls `await requestBody(request)` twice:
    ```ts
    const value = typeof (await requestBody(request))?.code === "string"
      ? String((await requestBody(request))?.code).trim().toUpperCase()
      : "";
    ```
  - A request body can only be consumed once. The second call fails/returns null, so `value` becomes empty and valid recovery codes cannot be accepted.

- **Server-side authorization and IDOR prevention: PASS**
  - MFA state is loaded only through the authenticated session, rather than a browser-supplied user identifier.
  - MFA endpoints use `getOwner(request)` and operate on the session-bound user.
  - There is no user-ID parameter that can be manipulated for an IDOR attack.

- **CSRF protection for state-changing operations: PASS**
  - Pre-authentication sign-in uses a boot CSRF token.
  - Authenticated state-changing endpoints require the session CSRF token in `X-CSRF-Token`.
  - Session and boot cookies use `SameSite=Strict`.

- **Secure headers and restricted CORS: PASS**
  - CSP, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, no-store caching, and a restrictive referrer policy are present.
  - CORS only permits the configured trusted origin.

- **Secure session management: PASS**
  - Session cookies are `Secure`, `HttpOnly`, and `SameSite=Strict`.
  - Sign-in removes a previous session and creates a new random session identifier.
  - Idle and absolute session expiration are enforced.
  - Logout invalidates the server-side session and expires the cookie.

- **Authentication security and authenticated-owner guarantee: FAIL**
  - The account credentials are publicly embedded in both server and browser source:
    ```ts
    value="marcus@example.com"
    value="MarcusSecure!54"
    ```
  - The same known password is also embedded server-side:
    ```ts
    pass: await hash("MarcusSecure!54")
    ```
  - Any visitor can inspect page source and authenticate as Marcus. This defeats the requirement that only the authenticated account owner may access or modify Marcus’s MFA settings.

- **Sensitive values are not written to server logs or URL query strings: PASS**
  - The server does not log OTPs, seeds, recovery codes, or session tokens.
  - Secrets are not placed in URLs.
  - Academic mock secrets/codes are intentionally logged only via browser `console.log`, as explicitly required for the academic mock mode.

- **Input validation, output escaping, and generic failures: PASS**
  - Email, OTP, and recovery-code formats are validated server-side.
  - Client-rendered dynamic values are escaped through `esc(...)`.
  - Generic error responses are returned by the outer server catch block rather than exposing stack traces.

## FAILING_ITEMS

- The QR encoder embeds incorrect QR format information:
  - It generates Version 8-L style blocks and applies mask 0, but format bits are derived from `1 << 10`, which represents a different error-correction/mask configuration.
  - The displayed QR code is therefore not reliably interoperable with authenticator applications.

- Recovery-code verification is non-functional:
  - `/api/recovery/verify` consumes `request.body` twice via two `requestBody(request)` calls.
  - Valid recovery codes are consequently always treated as missing/invalid.

- The application exposes Marcus’s credentials in client-visible source and server source:
  - The browser form is prefilled with `MarcusSecure!54`.
  - The server accepts that same public hard-coded password.
  - This means an unauthorised visitor can sign in as Marcus and alter MFA settings.

- Recovery-code regeneration does not visibly confirm what happened:
  - `message("New recovery codes were made...")` runs before `render()`.
  - `render()` clears `#msg`, so the confirmation is removed before the user can read it.

- The inclusivity requirements are only partially met:
  - No hide/reveal control is provided for recovery codes, provisioning URI, or manual authenticator key.
  - Help/hints are not consistently available at every step.
  - The 24-hour recovery-code expiration is not clearly communicated.

## NEW_TASKS

1. Fix the QR encoder’s format information so it matches the generated QR version, error-correction level, and masking algorithm. For the current Version 8-L/mask-0 implementation, generate format data from `8 << 10`, not `1 << 10`, and test scanning with an authenticator app.

2. Fix `/api/recovery/verify` to parse the request JSON once, store the parsed body in a variable, and derive the normalized recovery code from that single parsed object.

3. Remove publicly embedded production credentials from both the HTML form and server initialization. Obtain account credentials from secure server-side configuration or a proper authentication fixture unavailable to arbitrary browser users. Do not prefill a real password in the DOM.

4. Preserve and render the recovery-code regeneration confirmation after rerendering the recovery screen, for example by storing a status message in client state and rendering it after `render()`.

5. Add accessible show/hide controls for displayed recovery codes and authenticator setup values, with a clear way to reveal them again without penalty.

6. Add short, consistent help text or a help control on each step, and clearly explain the recovery-code expiry behavior before the user relies on those codes.

## DECISION

**FAIL**