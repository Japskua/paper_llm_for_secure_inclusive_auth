# MFA Enrolment for Online Banking — Software Description

Second user story in the security-versus-inclusivity experiment. Mirrors the
structure of the password-recovery study: identical security requirements across
three cases, with only the inclusivity specification varied.

## Scenario

Marcus is a 54-year-old self-employed contractor who has just opened an account
with an online bank. He manages the account through the bank's mobile web
application — a responsive website opened in a phone's browser. Following a
regulatory update, the bank requires customers to enrol in multi-factor
authentication before authorising payments above a threshold. Marcus signs in,
verifies his identity, sets up a time-based one-time passcode authenticator, and
stores a set of backup recovery codes.

## Cases

| Case | Inclusivity specification |
|------|---------------------------|
| 1 | None. Functional goal and fixed security requirements only. |
| 2 | Cognitive condition named only — "cognitive condition dyslexia", no further detail. |
| 3 | Detailed: description of dyslexia-related challenges plus eight concrete inclusivity requirements. |

## Cognitive condition

Dyslexia, contrasting with ADHD in the password-recovery study. The two make
different demands: ADHD centres on attention, memory and multi-step orientation,
whereas dyslexia centres on reading load, transcription of long strings, and
freedom from reading-based time pressure.

## Fixed security requirements

Five OWASP categories, held constant across all three cases: broken access
control, security misconfiguration, cryptographic failures, injection, and
identification and authentication failures. Emphasis differs from study 1
because the feature differs — OTP secret storage, backup-code handling, and
session rotation on authentication carry more weight here than password-reset
token hygiene.

## Relationship to the first study

Deliberately parallel so the two are comparable and neither can be dismissed as
stylistically different:

- Requirements files follow the same section order, heading style and boilerplate.
- The manipulation is the same shape: case 2 differs from case 1 by one clause in
  the persona sentence; case 3 adds an "Inclusivity requirements:" block.
- Case directory names are identical, so the analysis code is shared.
- Rubrics follow the same layout, and the item-to-construct mapping is identical,
  so the security constructs are directly comparable across studies.

One deliberate difference: study 1's security items 2 and 3 are reverse-worded,
which split the judge panel on interpretation. Study 2's items are all positively
worded, and reverse coding is configured per study rather than globally.
