# LLM Evaluation Scores: Best Artifact per Case

This folder holds the LLM judges' scores for the six artifacts that human
experts also evaluated. It uses the same layout as the human results in
[`../human_evaluations/`](../human_evaluations/), so the two can be compared
directly.

> **Before comparing with the human data, read
> [Labels that do not match the contents](#labels-that-do-not-match-the-contents).**
> Every value in these files is correct, but some security column labels name
> the wrong OWASP category, and story-2 inclusivity uses the wrong dimension
> names.

## Files

| File | Track | Values |
|---|---|---|
| `LLM Security Scores.xlsx` | security | 6 judges × 6 artifacts × 5 categories × 3 repeats |
| `LLM inclusivity Scores.xlsx` | inclusivity | 6 judges × 6 artifacts × 5 dimensions × 3 repeats |

## What is in them

### The six artifacts

The highest-scoring of the ten runs in each case, as chosen in
`../final_evaluations/results_v2/cross_study/05_best_run_per_case.csv`. In the
block headers, "BEST CASE=CASE 4" means run 4.

| Block | Columns | Artifact |
|---|---|---|
| User story 1, case 1 | C–Q | `password_recovery_health/case_1…/run_04` |
| User story 1, case 2 | R–AF | `password_recovery_health/case_2…/run_04` |
| User story 1, case 3 | AG–AU | `password_recovery_health/case_3…/run_05` |
| User story 2, case 1 | AV–BJ | `mfa_enrolment_banking/case_1…/run_01` |
| User story 2, case 2 | BK–BY | `mfa_enrolment_banking/case_2…/run_05` |
| User story 2, case 3 | BZ–CN | `mfa_enrolment_banking/case_3…/run_01` |

### The six judges

| Row | ID | Judge (model) |
|---|---|---|
| 4 | LLM-1 | Claude — `anthropic/claude-opus-5` |
| 5 | LLM-2 | Gemini — `google/gemini-3.6-flash` |
| 6 | LLM-3 | Mistral — `mistralai/mistral-medium-3-5` |
| 7 | LLM-4 | Kimi — `moonshotai/kimi-k3` |
| 8 | LLM-5 | Qwen — `qwen/qwen3.8-max` |
| 9 | LLM-6 | Grok — `x-ai/grok-4.5` |

The seventh panel member, `openai/gpt-5.6-sol`, is left out because it comes
from the same lab as the model that generated the code. That matches the
primary analysis.

> **Note on the judge panel.** Initially, the evaluation was run with seven
> judges. Based on discussions with academic reviewers, the GPT judge
> (`openai/gpt-5.6-sol`) scores were not included in the final evaluation.
> Its judgements remain in the dataset for transparency.

### One value

Each cell in rows 4–9 is **one judge's mean over the three items of one
category or dimension**, from one scoring repeat:

- **E-1, E-2, E-3** are the three independent times each judge scored each
  artifact.
- Values are **adjusted** scores: security items 2 and 3 are reverse-worded in
  the LLM rubric and have been inverted (`6 − x`), so a higher value always
  means more secure. Inclusivity has no reverse-worded items.
- With three items per category, each value is a multiple of ⅓. Most cells
  show four decimals (3.6667). Some story-1 security cells are truncated to two
  (3.66 for 11⁄3), which is up to 0.007 lower than the exact value.

### Provenance and verification

The values come from the raw judgements in
`../final_evaluations/results_v2/<story>/scores_long.csv`, column
`adjusted_score`. All 1,080 values (540 per file) were checked against that
source. Every one matches to within the rounding noted above, with a largest
difference of 0.0067.

## Sheet layout

Each workbook has one sheet, `Sheet1`.

| Rows | Contents |
|---|---|
| 1–3 | Block header (artifact), category or dimension label, repeat (E-1/E-2/E-3) |
| 4–9 | Raw values, one row per judge |
| 11–20 | **Per-judge means across the three repeats**: one column per artifact × category (B–AE). Row 20 averages the six judges. |
| 22–30, B–G | **Per-judge case averages**: each judge's mean over the five categories, one column per artifact (`US1:CASE 1` … `US2:CASE 3`) |
| 22–30, J–O | **Per-judge case SD**: the standard deviation of that judge's five category means, per artifact |
| 31 | Unlabelled `=AVERAGE` formulas under some case-average columns, apparently working cells |
| 32–49, A–M | **Averages across all six judges**, per category, one small table per artifact |
| 34–47, O–P | **Overall average per case** across all judges, repeats and categories, one table per story |

All tables below row 10 are `=AVERAGE(...)` formulas over rows 4–9. Nothing
in them is entered by hand.

## Labels that do not match the contents

### Security: three category labels are swapped

The LLM judges scored the rubric files in
`../final_evaluations/evaluation_rubrics/`. Those files list the categories in
OWASP 2021 order: access control, cryptography, injection, misconfiguration,
authentication. This spreadsheet keeps the columns in that order but labels
them with the OWASP Top 10:2025 codes in ascending order. That puts three
labels on the wrong category:

| Column label in this file | Items in the LLM rubric | Category actually in the column | Correct OWASP 2025 code |
|---|---|---|---|
| `A01:2025` | 1–3 | Broken Access Control | **A01:2025** ✓ |
| `A02:2025` | 4–6 | Cryptographic Failures | **A04:2025** |
| `A04:2025` | 7–9 | Injection | **A05:2025** |
| `A05:2025` | 10–12 | Security Misconfiguration | **A02:2025** |
| `A07:2025` | 13–15 | Authentication Failures | **A07:2025** ✓ |

The human file in `../human_evaluations/` **is** in OWASP 2025 order, with each
label matching its contents. To compare a category, pair the columns like this:

| Category | Human file column label | This file's column label |
|---|---|---|
| Broken Access Control | `A01:2025` | `A01:2025` |
| Security Misconfiguration | `A02:2025` | **`A05:2025`** |
| Cryptographic Failures | `A04:2025` | **`A02:2025`** |
| Injection | `A05:2025` | **`A04:2025`** |
| Authentication Failures | `A07:2025` | `A07:2025` |

The overall security score, the mean of all five categories, is unaffected by
the labels and can be compared directly.

### Inclusivity, user story 2: the dimensions are dyslexia-specific

For user story 1 (ADHD), the columns are what they say: Attention, Memory,
Comprehension, Decision-making, Learning.

For user story 2 (dyslexia), the LLM judges scored a different rubric, whose
dimensions are readability, reading load, transcription, orientation and
recovery. The columns still carry the story-1 names:

| Column label in this file | Items | Dimension actually in the column (story 2) |
|---|---|---|
| Attention | 1–3 | Readability |
| Memory | 4–6 | Reading load |
| Comprehension | 7–9 | Transcription |
| Decision-making | 10–12 | Orientation |
| Learning | 13–15 | Recovery |

The human evaluators used the Attention / Memory / Comprehension /
Decision-making / Learning dimensions for **both** stories. For user story 2,
the human and LLM instruments therefore measure different dimensions. Compare
them at the overall-score level only, not dimension by dimension.

## How these numbers relate to the main analysis

These files are built for comparison with human raters, and they differ from
the primary LLM analysis in `../final_evaluations/results_v2/` in three ways:

| | This folder | Primary analysis |
|---|---|---|
| Artifacts | the 6 best runs | all 60 runs |
| Combining judges | **mean** of six judges | **median** of judges |
| Mistral, story 1 security | **included** | excluded as non-discriminating |

On the last point: Mistral gave story-1 security a fixed response pattern,
5 on every positively worded item regardless of the artifact. It is visible
here as row 6, which is all 5s in the story-1 security blocks. The primary
analysis drops it for that track because its artifact-level SD was 0.008
against 0.16–0.31 for every other judge (see
`../final_evaluations/results_v2/README.md`, §7). It is included here, which
pulls the story-1 security averages up. For a human-vs-LLM comparison
consistent with the paper, exclude row 6 from the story-1 security blocks.

Because of these differences, averages in this folder will not exactly match
the case figures in `../final_evaluations/results_v2/cross_study/`.

## Related resources

- **Human ratings of the same six artifacts**: `../human_evaluations/`
- **The six artifacts**: `../human_evaluation_package/`
- **All LLM judgements, with per-item justifications**: `../final_evaluations/results_v2/`
- **The rubrics the LLM judges scored**: `../final_evaluations/evaluation_rubrics/`
