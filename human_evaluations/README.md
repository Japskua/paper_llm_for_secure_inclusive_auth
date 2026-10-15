# Human Evaluations: Expert Assessment Results

This directory contains the ratings human experts gave the LLM-generated
applications for security and inclusivity.

## Overview

The experts assessed the **six best-scoring artifacts** from the repeated-runs
study, one per case for each of the two user stories. They are the same six
artifacts packaged in [`../human_evaluation_package/`](../human_evaluation_package/).

| | User story 1 | User story 2 |
|---|---|---|
| Application | Password recovery, health portal | MFA enrolment, online banking |
| Cognitive condition | ADHD | Dyslexia |
| Case 1 — no inclusivity specification | `run_04` | `run_01` |
| Case 2 — condition named | `run_04` | `run_05` |
| Case 3 — detailed guidance | `run_05` | `run_01` |

The ratings were collected through online surveys using
[Webropol](https://webropol.com/).

## Files

| File                                  | Evaluators | Items | Cases | Description                        |
| ------------------------------------- | ---------- | ----- | ----- | ---------------------------------- |
| `inclusivity_evaluation_results.xlsx` | 10         | 15    | 6     | Cognitive accessibility assessment |
| `security_evaluation_results.xlsx`    | 10         | 15    | 6     | OWASP-based security assessment    |

Each cell is one evaluator's 1–5 rating of one item for one artifact: 10
evaluators × 15 items × 6 artifacts = 900 ratings per file, none missing.

| | Inclusivity | Security |
|---|---|---|
| Evaluators | P1–P10 | P1–P10 |
| Years of experience, mean (SD) | 8.7 (5.1) | 6.6 (3.7) |
| Years of experience, range | 3–16 | 1–12 |

IDs are assigned per file. `P1` in the inclusivity file and `P1` in the
security file are not necessarily the same person, and the files do not record
whether anyone took part in both.

## Inclusivity Evaluation

### Evaluation Dimensions

The 15-item rubric covers five cognitive dimensions, three items each, and is
the same for both user stories:

| Dimension       | Items | Focus Area                                                 |
| --------------- | ----- | ---------------------------------------------------------- |
| Attention       | 1-3   | UI cleanliness, element prominence, quick navigation       |
| Memory          | 4-6   | Minimal recall requirements, recall aids, recognition      |
| Comprehension   | 7-9   | Text clarity, error messages, examples                     |
| Decision Making | 10-12 | Clear choices, limited options, action feedback            |
| Learning        | 13-15 | Help tips, error recovery, consistency                     |

The wording is adapted to each application where needed. Item 5, for example,
asks about password managers and autofill in user story 1 and about
copy-to-clipboard and QR codes in user story 2.

### Evaluation Input

- The six applications, live and clickable, each evaluator on a private
  instance (see `../human_evaluation_package/JUDGE_LINKS.md`)
- Inclusivity evaluation rubric

## Security Evaluation

### Evaluation Dimensions

The 15-item rubric covers five **OWASP Top 10:2025** categories, three items
each:

| OWASP Category                         | Items | Focus Area                                                            |
| -------------------------------------- | ----- | --------------------------------------------------------------------- |
| A01:2025 Broken Access Control         | 1-3   | Codes bound to the right account, session handling, forged requests   |
| A02:2025 Security Misconfiguration     | 4-6   | Secrets kept out of logs and errors, secure defaults, browser settings |
| A04:2025 Cryptographic Failures        | 7-9   | HTTPS/TLS, encryption and hashing, secure randomness, secret storage   |
| A05:2025 Injection                     | 10-12 | Input sanitisation, safe redirects, safe output and templates         |
| A07:2025 Authentication Failures       | 13-15 | Attempt limiting, no account enumeration, strong single-use codes     |

The wording is adapted to each application (reset codes in user story 1, MFA
and backup codes in user story 2), but the categories and item positions are
the same in both. All items are worded so that agreeing means more secure; no
reverse coding is needed.

### Evaluation Input

- Full source code (`app.ts`) of each artifact, from
  `../human_evaluation_package/source_code/`
- Security evaluation rubric

## Scoring Scale

All items use a 5-point Likert scale:

| Score | Security Interpretation | Inclusivity Interpretation |
| ----- | ----------------------- | -------------------------- |
| 1     | Critically Insecure     | Strongly Disagree          |
| 2     | Insecure                | Disagree                   |
| 3     | Neutral                 | Neutral                    |
| 4     | Secure                  | Agree                      |
| 5     | Most Secure             | Strongly Agree             |

**Maximum possible score**: 75 (15 items × 5 points)

## File Structure

Both workbooks have a single sheet, `Sheet1`, laid out the same way.

**Header rows**

| Row | Contents |
|---|---|
| 1 | Artifact, at the first column of each block (e.g. `User Story 1: Case 1`) |
| 2 | Dimension or OWASP category, at the first column of each 3-item group |
| 3 | Full item text |

**Data rows**

| Rows | Contents |
|---|---|
| 4–13 | One row per evaluator: column A is the ID (`P1`–`P10`), column B is years of experience, then the 90 ratings |
| 14–15 | Mean and standard deviation of years of experience (column B) |
| 17 onward | Per-dimension averages for each artifact, as `=AVERAGE(...)` formulas over that block's 10 × 3 ratings |

**Column blocks** — 15 columns each, one per artifact:

| Columns | Artifact |
|---|---|
| C–Q | User story 1, case 1 |
| R–AF | User story 1, case 2 |
| AG–AU | User story 1, case 3 |
| AV–BJ | User story 2, case 1 |
| BK–BY | User story 2, case 2 |
| BZ–CN | User story 2, case 3 |

Within a block, items run 1–15 left to right in the order of the tables above.

## Comparing with the LLM judges

The LLM panel's scores for the same six artifacts are in
[`../llm_evaluation_scores_computed/`](../llm_evaluation_scores_computed/),
arranged in the same block layout. **Read that folder's README before
comparing**, for two reasons:

- **Security:** both files use 2025 category labels, but the LLM file's labels
  do not match its contents. Under the same label, the two files hold different
  categories.
- **Inclusivity, user story 2:** the LLM judges scored a dyslexia-specific
  rubric, while the human evaluators scored the five dimensions above. Compare
  the two at the overall-score level only.

The human and LLM rubrics also word their items differently, so compare by
category, not by item number.

## Related Resources

- **Survey instruments**: See `../survey_questionnaires/` for the PDF questionnaires used
- **The evaluated artifacts**: See `../human_evaluation_package/` for the source code and the deployment the evaluators used
- **LLM evaluations**: See `../llm_evaluation_scores_computed/` for the LLM scores of the same six artifacts, and `../final_evaluations/results_v2/` for the full LLM dataset
- **Evaluation rubrics**: See `../final_evaluations/evaluation_rubrics/` for the rubrics the LLM judges used

## Ethics

- All participants provided informed consent
- No personally identifiable information (PII) was collected
- Participation was voluntary and anonymous
