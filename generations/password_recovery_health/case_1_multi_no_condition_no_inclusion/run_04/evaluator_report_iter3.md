## SUMMARY

The artifact is structurally close to the requested single-file Bun application and includes many intended security controls (TLS, CSP nonce, CSRF, session-bound reset tokens, rate limiting, MFA, Argon2id hashing, and safe client-side DOM rendering). However, the password recovery flow is not reliably functional: creating a reset record invokes an effectively unbounded brute-force loop to rediscover an already-generated MFA code from its SHA-256 hash. This will commonly hang the reset-request endpoint for a very long time, preventing token delivery and making the required recovery flow fail.

## FUNCTIONAL_CHECK

- **Single-file `app.ts` Bun server with HTML, CSS, and vanilla browser JavaScript: PASS**
  - The server, HTML template, CSS, and client JavaScript are all contained in `app.ts`.
  - It uses Bun directly and does not require a bundler, framework, external CDN, or compilation pipeline beyond Bun executing TypeScript.

- **Bun TLS server uses `certs/cert.pem` and `certs/key.pem`: PASS**
  - `Bun.serve` is configured with the specified certificate paths.
  - The handler rejects requests whose URL protocol is not HTTPS.

- **Password recovery request works and avoids account enumeration: FAIL**
  - The response wording is generic for recognized and unrecognized accounts, which is correct.
  - However, a valid designated test-account request calls the overridden `resetTokens.set`, which repeatedly generates random 8-digit values until one SHA-256 hash matches the pre-existing MFA hash. This is approximately a 1-in-100,000,000 chance per attempt and can stall the request indefinitely.

- **Reset token is random, opaque, short-lived, session-bound, and single-use: PASS (logic), FAIL (end-to-end usability)**
  - Tokens are generated using `randomBytes`, stored by SHA-256 hash, expire after 10 minutes, are tied to the current session, and are removed after reset.
  - In practice, the token is not reliably delivered because reset-record creation can hang.

- **Verification link and manual token submission both function: FAIL**
  - The UI supports a reset-link route (`/?screen=verify&token=...`) and a manual token-entry screen.
  - Neither can be reliably reached in a completed flow because the reset request may not finish due to the MFA delivery-code loop.

- **MFA verification works: FAIL**
  - The intended flow verifies a hashed MFA code and throttles incorrect attempts.
  - The code that should populate `mfaDeliveryCodes` is computationally infeasible/reliability-breaking, so the MFA delivery and therefore MFA verification cannot be considered functional.

- **Password policy and secure password storage: PASS**
  - The application enforces at least 12 characters, upper-case, lower-case, number, and symbol requirements.
  - On reset, it hashes passwords using Bun Argon2id before storing them.
  - Passwords are not returned to the client or logged.

- **CSRF protection on sensitive requests: PASS**
  - A random CSRF token is generated per session.
  - All `POST /api/*` routes validate `X-CSRF-Token`.
  - The session cookie uses `Secure`, `HttpOnly`, and `SameSite=Strict`.

- **Access control / IDOR protections: PASS**
  - Reset records are bound to the session that initiated them.
  - Reset, MFA, and password update require the appropriate preceding state.
  - Privacy acceptance requires an authenticated recovery session.
  - Session-status data exposes only boolean status values.

- **XSS and injection protections: PASS**
  - Browser-generated UI uses `textContent`, `createElement`, and `replaceChildren` rather than unsafe HTML insertion.
  - The CSP uses a per-response nonce and forbids untrusted scripts.
  - User input is not reflected as HTML.

- **Security headers and cache controls: PASS**
  - HSTS, CSP, `X-Content-Type-Options`, frame restrictions, referrer policy, permissions policy, COOP/CORP, and no-store cache headers are configured.

- **Brute-force throttling: PASS**
  - Recovery, token verification, and MFA checks have server-side attempt limits over a 15-minute window.
  - Limits are keyed using a normalized identifier plus a server-derived coarse client network key.

- **Safe-authentication and anti-phishing guidance: PASS**
  - The UI clearly warns users not to disclose passwords, reset tokens, or verification codes to staff/support callers.
  - No external redirect or outbound URL behavior is present.

- **Mocks delivered through browser console/UI: PARTIAL FAIL**
  - The client correctly logs simulated reset tokens and MFA codes in the browser console and Logs panel when responses are received.
  - Due to the reset-record creation hang, those simulated values are not reliably returned or logged.
  - The stated requirement calls for deterministic mock values, but the MFA mock code is random and is handled through an unreliable hash-preimage reconstruction mechanism.

## FAILING_ITEMS

- **Critical functional defect: MFA delivery-code generation can hang the server request.**
  - `newMfaCode()` creates a random MFA code and stores only its hash.
  - The overridden `resetTokens.set` then attempts to regenerate random codes until one hashes to the existing value:
    ```ts
    if (sha256(code) === record.mfaCodeHash) {
      mfaDeliveryCodes.set(tokenHash, code);
      break;
    }
    ```
  - Since this requires finding a SHA-256 preimage within an 8-digit code space by random guessing, it takes roughly 100 million attempts on average. The reset request can block for a long time or appear permanently frozen.

- **The recovery flow therefore does not satisfy the requirement that verifications must work.**
  - A requester cannot dependably receive a reset token response, simulated MFA delivery, or proceed through reset/MFA/privacy completion.

- **The MFA mock implementation is not deterministic as required.**
  - Reset tokens should remain cryptographically random, but the simulated test delivery mechanism should use a direct, testable, deterministic/mock value or retain the generated code securely in the in-memory mock transport.
  - Recreating an unknown random value from its hash is not a valid mock-delivery strategy.

- **Expired/removed reset records leave associated MFA delivery entries behind.**
  - `cleanOldState()` removes entries from `resetTokens` but does not remove matching entries from `mfaDeliveryCodes`.
  - This creates unnecessary in-memory retention of simulated MFA codes until some later path deletes them.

## NEW_TASKS

1. Remove the `resetTokens.set` monkey-patch and its brute-force SHA-256 preimage loop entirely.

2. Change reset-record creation so `newMfaCode()` returns the generated plaintext MFA mock code and its hash, then immediately store the plaintext code in `mfaDeliveryCodes` under the token hash while storing only the hash in `ResetRecord`.

3. Ensure the simulated MFA code is directly retrievable after successful token verification and is logged by the existing browser-side `console.log` flow.

4. Update `cleanOldState()` to delete the corresponding `mfaDeliveryCodes` entry whenever an expired or used reset token is deleted.

5. Test the complete browser flow on HTTPS:
   1. request reset using the designated test email,
   2. confirm the reset token appears in browser console/Logs,
   3. verify through both the generated link and manual token entry,
   4. confirm the MFA code appears in browser console/Logs,
   5. submit MFA code,
   6. reset with a compliant password,
   7. accept privacy terms,
   8. confirm the completion screen.

## DECISION

**FAIL**