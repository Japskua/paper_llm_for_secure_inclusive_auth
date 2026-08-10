## SUMMARY

The artifact is structurally close to the requested design: it is a single `app.ts`, uses Bun HTTPS/TLS, has substantial server-side authorization, CSRF, headers, encryption/hashing, rate limiting, and a mobile-oriented SPA. However, it cannot be accepted because it contains server-side TypeScript syntax that prevents execution and client-side JavaScript syntax that prevents the entire UI script from parsing. It also presents a decorative “QR-style” image rather than a usable QR code for the provisioning URI.

## FUNCTIONAL_CHECK

- **Single-file Bun server with inline HTML, CSS, and vanilla JavaScript: PASS**
  - The server, SPA template, CSS, and client JavaScript are all contained in `app.ts`.
  - No frameworks, bundlers, external assets, or network calls are used.

- **HTTPS/TLS using `certs/cert.pem` and `certs/key.pem`: PASS**
  - `Bun.serve` is configured with `tls.cert` and `tls.key` using the required paths.

- **Server starts and serves a functioning app directly: FAIL**
  - `payload()` contains invalid TypeScript/JavaScript: `return ... ? x:any;`.
  - `any` is used as an expression rather than a value such as `null`, causing a parsing/transpilation failure.

- **Client-side SPA interactivity works in the browser: FAIL**
  - The client script contains `new.onclick=...`. `new` is a reserved JavaScript keyword, making the browser script invalid.
  - Because this is a syntax error, the complete inline client script fails to parse, so sign-in and all MFA UI interactions do not run.

- **Authenticator provisioning supports QR and manual secret entry: FAIL**
  - The secret and provisioning URI are returned and displayed, and the secret can be copied.
  - However, `.qr` is only a CSS striped decorative block, not an actual QR code that encodes the `otpauth://` URI. It cannot be scanned by an authenticator app.

- **Copy-to-clipboard support works: FAIL**
  - The button with `id="copy"` is assigned through `copy.onclick`.
  - A global function named `copy()` already exists, so this refers to the function object rather than reliably selecting the button. The “Copy secret” button handler is not correctly attached.

- **OTP verification is functional, time-bound, and single-use: PASS by server-side inspection**
  - TOTP uses HMAC-SHA1 with 30-second periods and accepts only current/adjacent periods.
  - Accepted TOTP counter values are retained in `usedTotp`, preventing reuse.
  - This functionality is presently unreachable through the broken client script.

- **Backup recovery codes are securely generated, stored, and single-use: PASS by server-side inspection**
  - Production codes are generated with `crypto.getRandomValues`.
  - Codes are stored as keyed HMAC values rather than plaintext.
  - Used recovery codes are removed from the active list and retained as used hashes.

- **Authentication, authorization, IDOR prevention, and CSRF protections: PASS by server-side inspection**
  - MFA routes derive the account only from the HttpOnly session cookie and do not accept user IDs from the client.
  - State-changing authenticated routes require same-origin requests and a server-issued CSRF token.
  - Session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict`.

- **Security headers and browser protections: PASS by server-side inspection**
  - CSP with nonces, HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy`, and no-store caching are configured.
  - CORS is restricted to the local trusted origins.

- **Rate limiting and lockout for verification attempts: PASS by server-side inspection**
  - OTP and recovery-code verification track failures and apply a five-minute lockout after five failures.

- **Dyslexia-friendly, mobile-oriented UX: PARTIAL / FAIL**
  - The design includes spacious layout, readable sizing, short instructions, examples, help details, no timers, and mobile responsive styling.
  - It does not function due to the client syntax error, and the fake QR image fails the requirement to reduce manual transcription through a real scannable QR option.

## FAILING_ITEMS

- `payload()` has invalid code:
  - `return x&&typeof x==="object"&&!Array.isArray(x)?x:any;`
  - Replace `any` with a runtime value such as `null`. As written, the server cannot be reliably parsed/transpiled by Bun.

- The browser script has a fatal syntax error:
  - `new.onclick=async()=>{...}`
  - `new` is reserved syntax in JavaScript. This prevents the entire client script from loading.

- The “Copy secret” button is not correctly bound:
  - `copy` is both a declared function and a button ID.
  - `copy.onclick` resolves to the function binding, not a safe element reference.

- The QR element is not a QR code:
  - The CSS `repeating-linear-gradient` block does not encode the provisioning URI and is not scannable.
  - The application claims users can scan it, which is misleading and fails the QR-code option requirement.

## NEW_TASKS

1. Fix `payload()` so invalid JSON or invalid payload shapes return `null`:
   - Replace `?x:any` with `? x : null`.

2. Fix the fatal client JavaScript syntax error:
   - Rename the `id="new"` button to a non-reserved identifier such as `id="regenerate"`.
   - Bind the handler using an explicit DOM lookup, for example `document.querySelector("#regenerate").onclick = ...`.

3. Fix button event binding collisions:
   - Do not rely on browser-created global variables from element IDs.
   - Use explicit selectors for `#copy`, `#link`, `#added`, `#check`, `#all`, and other interactive controls.
   - Rename the `copy()` helper to a non-conflicting name such as `copyText()`.

4. Implement a real, scannable QR code for the generated `otpauth://` URI without external assets or network calls:
   - Generate a valid QR matrix client-side or server-side from `uri`.
   - Render it as SVG, canvas, or an accessible image/data URI.
   - Keep the displayed/copyable secret and provisioning URI as the manual fallback.

## DECISION

**FAIL**