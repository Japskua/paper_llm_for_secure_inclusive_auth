# Survey Questionnaires: Evaluation Instruments

This directory contains the PDF exports of the two online surveys used for the
human expert evaluation. The results are in
[`../human_evaluations/`](../human_evaluations/).

## Files

| File | Pages | Size | Purpose |
|------|-------|------|---------|
| `inclusivity_evaluation_survey.pdf` | 15 | 1.8 MB | Cognitive accessibility assessment of the live applications |
| `security_evaluation_survey.pdf` | 14 | 1.4 MB | OWASP Top 10:2025 assessment of the source code |

Both are exports from [Webropol](https://webropol.com/), the platform used to
run the surveys.

## What was evaluated

The six best-scoring artifacts from the repeated-runs study: one per case, for
each of two user stories. They are packaged in
[`../human_evaluation_package/`](../human_evaluation_package/).

| | User story 1 | User story 2 |
|---|---|---|
| Persona | Helena, 67, chronic heart disease | Marcus, 54, self-employed contractor |
| Task | Reset a forgotten password to accept updated privacy terms | Enrol in multi-factor authentication before authorising larger payments |
| Application | Password recovery, hospital patient portal | MFA enrolment, online banking (mobile web) |
| Cognitive condition | ADHD | Dyslexia |

| Case | Inclusivity specification given to the code-generating model |
|------|-----|
| **Case I**: No inclusivity specification | None; no cognitive condition mentioned. The baseline for the model's default behaviour. |
| **Case II**: Moderate | The condition is named in the user story, nothing more. |
| **Case III**: Detailed | The condition is described, with concrete inclusivity requirements. |

The security requirements were the same in all six cases.

## Survey Structure

The two surveys share the same structure:

1. **Survey statement**: study context, the three research questions, and an
   estimated completion time of about 30 minutes
2. **Consent**: mandatory participation consent; no personally identifiable
   information collected
3. **Background**: current role and number of years of experience
4. **Six case sections**: user story 1 cases I–III, then user story 2 cases
   I–III. Each section gives the user story and the case's inclusivity
   specification, a link to the artifact, and the 15 rating items.
5. **15 items per case**: five dimensions × three items, all mandatory

Each survey therefore collects 90 ratings per evaluator.

Case III sections reproduce the full condition description and the additional
requirements from the generation prompt, so evaluators see what the model was
asked to do.

## Inclusivity Evaluation Survey

Evaluators use each application and rate how well it suits a user with the
story's cognitive condition.

### Evaluator Input

- **The live application.** Each case links to that artifact's Cloudflare
  deployment, e.g.
  `https://llm-auth-s2-case3.japskua.workers.dev/?judge=6`. The survey gives
  two links per case, and evaluators use one of them.
- **Account details.** For user story 1, a demo email is given in the survey.
  For user story 2, the test credentials are shown on the application page.

### Evaluation Dimensions

The same five dimensions are used for both user stories:

| Dimension | Items | Example Criteria |
|-----------|-------|------------------|
| **Attention** | 1-3 | Clean UI without moving images or pop-ups, important items stand out, easy to find what to do |
| **Memory** | 4-6 | Few rules or steps to remember, recall aids, recognisable information and options |
| **Comprehension** | 7-9 | Short clear text, error messages that explain the fix, examples of what to type |
| **Decision Making** | 10-12 | Clear choices, not too many at once, clear outcome of each action |
| **Learning** | 13-15 | Help or tips for new steps, easy to retry after a mistake, consistent design |

Two Memory items are worded differently for the two stories. The other 13 are
the same:

| Item | User story 1 | User story 2 |
|---|---|---|
| 5 | Password manager, autofill or "remember me" options are present | Copy-to-clipboard or QR-code options remove the need to type long codes |
| 6 | The user can easily recognise saved or familiar items | The user can easily recognise the information and options needed for each step |

All statements are positively keyed, so higher scores mean greater
inclusivity. No reverse coding is needed.

## Security Evaluation Survey

Evaluators read each artifact's source code and rate it against OWASP Top
10:2025 criteria.

### Evaluator Input

- **The source code** of each artifact, linked from the survey to the public
  repository
  [`LLM4Code-inclusivitysecurity/securityevaluation`](https://github.com/LLM4Code-inclusivitysecurity/securityevaluation).
  Its six `.ts` files are byte-identical to
  `../human_evaluation_package/source_code/`. Their SHA-256 hashes match
  `MANIFEST.csv` and the generation manifests.
- **The user story and the case's inclusivity specification**, shown as
  context for each section.

### Evaluation Dimensions

| OWASP Category | Items | User story 1 (password recovery) | User story 2 (MFA enrolment) |
|----------------|-------|------------------|------------------|
| **A01:2025 Broken Access Control** | 1-3 | Reset code belongs to the requester; no cross-account use; sessions ended on reset | MFA setup tied to the logged-in account; codes usable only on their own account; no setup through cross-site requests |
| **A02:2025 Security Misconfiguration** | 4-6 | No secrets in errors or logs; nothing hard coded; no default credentials | No secrets in logs, links or errors; secure cookies and framing protection; trusted origins only, no default passwords, no technical error details |
| **A04:2025 Cryptographic Failures** | 7-9 | HTTPS with current TLS; strong encryption or hashing; secure randomness | HTTPS with current TLS; MFA secrets and backup codes securely generated and protected; no tokens or secrets in browser storage |
| **A05:2025 Injection** | 10-12 | Input validated and sanitised; redirects stay on site; email templates script-free | Input sanitised; links stay on the bank's site; user text cannot run scripts |
| **A07:2025 Authentication Failures** | 13-15 | Repeated failed attempts blocked; no account enumeration; random single-use reset codes | Attempts blocked after repeated wrong codes; no account enumeration; random, one-time, short-lived codes |

All items are worded so that agreeing means more secure. No reverse coding is
needed.

## Scoring Scale

Both surveys use the same 5-point Likert scale:

| Score | Label |
|-------|-------|
| 1 | Strongly disagree |
| 2 | Disagree |
| 3 | Neutral |
| 4 | Agree |
| 5 | Strongly agree |

## Notes for interpreting the results

- **Evaluators were not blind to the case.** Both surveys name each section by
  its case and inclusivity level. In the security survey, the code file names
  also state the condition (e.g. `…__case3_detailed_guidance.ts`). The LLM
  judges had the same exposure through their per-case rubrics.
- **Live instances may have been shared.** Each case offers two links, and
  each link opens one application instance, keyed by its `judge` ID. With more
  evaluators than links, several evaluators will have used the same instance.
  The applications keep account state in memory: a completed MFA enrolment,
  used backup codes, or a lockout after repeated failed sign-ins carries over to
  the next person on that instance (see
  `../human_evaluation_package/deploy_cloudflare/README.md`). Inclusivity
  ratings for the stateful flows may therefore reflect what an earlier
  evaluator did.
- **The human and LLM instruments differ.** Both use the same five OWASP
  categories and five cognitive dimensions, but the item wording is different.
  For user story 2, the LLM judges scored dyslexia-specific dimensions
  (readability, reading load, transcription, orientation, recovery) rather than
  the five above. See `../llm_evaluation_scores_computed/README.md` before
  comparing.

## Related Resources

- **Evaluation results**: See `../human_evaluations/` for the expert ratings
- **Evaluated artifacts**: See `../human_evaluation_package/` for the source code and the live deployment
- **LLM scores for the same artifacts**: See `../llm_evaluation_scores_computed/`
- **LLM evaluation rubrics**: See `../final_evaluations/evaluation_rubrics/` for the rubrics the LLM judges used
- **Generation prompts**: See `../requirements/` for the full prompt behind each case
