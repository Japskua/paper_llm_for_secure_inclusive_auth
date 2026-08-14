# Final Evaluations: Rubrics and Results

Evaluation instruments and LLM-based assessment results for the security and
inclusivity evaluation of LLM-generated code.

## There are two separate result sets. Read this first.

`results/` and `results_v2/` are **different experiments**, not two versions of
one. `results_v2/` did not replace, revise or recompute anything in `results/`;
the older data is untouched.

| | `results/` | `results_v2/` |
|---|---|---|
| Collected | Oct 2025 – Feb 2026 | Aug 2026 |
| Design | 1 run per case | **10 runs per case** |
| User stories | 1 (password recovery, ADHD) | **2** (adds MFA enrolment, dyslexia) |
| Artifacts | 3 | **60** |
| Judges | 5 | **7**, one per lab |
| Repeats per judge | 1 | **3** |
| Judgements | 30 result files | **2,457** |
| Generator | `openai/gpt-5` | `openai/gpt-5.6-terra` |
| Collection | manual, pasted into text files | scripted, resumable, hash-verified |
| Reporting | totals out of 75 | artifact-level means, non-parametric tests, ICC/α |
| Status | archival; as published | **current; use for the revision** |

**Why the second data set exists.** Reviewers asked whether a single generation
per case could support the claim. It cannot: one run cannot separate a real
effect from run-to-run variance, and n=1 admits no inferential statistics. The
2026 collection re-runs the design ten times per case, adds a second user story
with a different application domain and a different cognitive condition, and
judges everything three times over with a larger panel.

**Which to cite.** For the revised paper, `results_v2/`. Cite `results/` only
when referring to the original submission. Do not pool them — different
generator, different panel, different aggregation.

> `results_v2/` has its own complete, standalone documentation:
> **[results_v2/README.md](results_v2/README.md)** — the judge panel and why each
> model was chosen, the scoring protocol, the record schema, CSV columns,
> aggregation order, statistical methods, every exclusion, limitations, and
> reproduction commands. Anyone analysing the 2026 data should start there and
> needs nothing else.

## Directory Structure

```
final_evaluations/
├── README.md                        this file
├── judge_panel.json                 the 2026 panel: 7 judges, plus candidates
│                                    considered and rejected, with reasons
├── evaluation_rubrics/              evaluation questionnaires, 15 items each
│   ├── security_eval_case_{1,2,3}.md          study 1 — password recovery, ADHD
│   ├── inclusivity_eval_case_{1,2,3}.md
│   └── mfa_enrolment_banking/                 study 2 — MFA enrolment, dyslexia
│       ├── security_eval_case_{1,2,3}.md
│       └── inclusivity_eval_case_{1,2,3}.md
├── results/                         2025 single-run study  (archival)
│   ├── security/case_{1,2,3}/
│   └── inclusivity/case_{1,2,3}/
└── results_v2/                      2026 repeated-runs study  (current)
    ├── README.md                    ← standalone guide to everything below
    ├── password_recovery_health/    study 1: 30 artifacts, ADHD
    ├── mfa_enrolment_banking/       study 2: 30 artifacts, dyslexia
    └── cross_study/                 combined tables, both report variants,
                                     all_results.xlsx
```

Rubrics are shared: both studies were judged with the same per-case rubric files
that the 2025 study used, taken verbatim, so the instrument is not a confound
between the two collections.

## Evaluation Rubrics

Three cases per study, varying **only** the inclusivity specification:

| Case | Inclusivity specification |
|------|---------------------------|
| 1 | none — functional goal and security requirements only |
| 2 | condition named, nothing more |
| 3 | condition described, with concrete inclusivity requirements |

### Security Evaluation (15 items)

Based on OWASP Top 10 (2021), assessing five categories. **Identical in both
studies and in both collections**, so security is comparable throughout:

| Category | Items | OWASP Code |
|----------|-------|------------|
| Broken Access Control | 1-3 | A01:2021 |
| Cryptographic Failures | 4-6 | A02:2021 |
| Injection/XSS | 7-9 | A03:2021 |
| Security Misconfiguration | 10-12 | A05:2021 |
| Authentication Failures | 13-15 | A07:2021 |

Items 2 and 3 are reverse-worded — agreeing means the system is *less* secure —
and are inverted (`6 − x`) before aggregation in `results_v2/`. The rule is the
same in both studies by design.

### Inclusivity Evaluation (15 items)

Five cognitive dimensions, but **the dimensions differ by study**, because the
studies target different conditions:

| Items | Study 1 — ADHD | Study 2 — dyslexia |
|-------|----------------|--------------------|
| 1-3 | Attention | Readability |
| 4-6 | Memory | Reading load |
| 7-9 | Comprehension | Transcription |
| 10-12 | Decision making | Orientation |
| 13-15 | Learning | Recovery |

> Inclusivity may be compared between the studies at the **overall score** level
> only. Construct-level comparison across studies is meaningless.

### Scoring Scale

All items use a 5-point Likert scale:

| Score | Security Interpretation | Inclusivity Interpretation |
|-------|------------------------|---------------------------|
| 1 | Critically Insecure | Strongly Disagree |
| 2 | Insecure | Disagree |
| 3 | Neutral | Neutral |
| 4 | Secure | Agree |
| 5 | Most Secure | Strongly Agree |

`results/` reports totals out of 75 (15 items × 5). `results_v2/` reports means
on the 1–5 scale instead, because artifacts there have differing numbers of
scoreable items and a mean stays interpretable.

---

# `results/` — 2025 single-run study (archival)

One artifact per case, three artifacts total, each judged once by five models.

The scored artifacts are in
`../workspace/password_recovery_health/<case>/legacy_single_run_gpt4o/`. Despite
the directory name, the recorded token pricing in `tokens_summary.json` is
GPT-5's — the name comes from a stale `OPENROUTER_MODEL=openai/gpt-4o` example in
the root README, corrected in commit `2c980c3`. Screenshots are in
`../screenshots/<case>/`.

## LLM Evaluators

| Model | Provider | Evaluation Input |
|-------|----------|------------------|
| GPT-5 | OpenAI | Source code (security) / Screenshots (inclusivity) |
| Claude Sonnet 4.5 | Anthropic | Source code (security) / Screenshots (inclusivity) |
| Gemini 2.5 Pro | Google | Source code (security) / Screenshots (inclusivity) |
| Mistral Medium 3.1 | Mistral AI | Source code (security) / Screenshots (inclusivity) |
| DeepSeek 3.2 | DeepSeek | Source code (security) / Screenshots (inclusivity) |

## Result File Format

Each result file contains 15 numeric scores:

```
1: [score]
2: [score]
...
15: [score]
```

### File Naming Convention

```
results/{security|inclusivity}/case_{N}/case_{N}_{model-name}.txt
```

**Examples:**
- `results/security/case_1/case_1_gpt-5.txt`
- `results/inclusivity/case_3/case_3_claude-sonnet-4-5.txt`

## Summary Statistics

### Security Evaluation Totals (out of 75)

| Evaluator | Case 1 | Case 2 | Case 3 | Mean |
|-----------|--------|--------|--------|------|
| GPT-5 | 52 | 58 | 55 | 55.0 |
| Claude Sonnet 4.5 | 75 | 67 | 74 | 72.0 |
| Gemini 2.5 Pro | 62 | 57 | 63 | 60.7 |
| Mistral Medium 3.1 | 67 | 67 | 71 | 68.3 |
| DeepSeek 3.2 | 66 | 73 | 70 | 69.7 |
| **Case Mean** | **64.4** | **64.4** | **66.6** | |

### Inclusivity Evaluation Totals (out of 75)

| Evaluator | Case 1 | Case 2 | Case 3 | Mean |
|-----------|--------|--------|--------|------|
| GPT-5 | 67 | 63 | 69 | 66.3 |
| Claude Sonnet 4.5 | 49 | 56 | 70 | 58.3 |
| Gemini 2.5 Pro | 52 | 61 | 65 | 59.3 |
| Mistral Medium 3.1 | 53 | 53 | 62 | 56.0 |
| DeepSeek 3.2 | 56 | 55 | 62 | 57.7 |
| **Case Mean** | **55.4** | **57.6** | **65.6** | |

"Case Mean" is the mean total across the five evaluators for that one artifact —
a descriptive figure only. With one artifact per case there is no within-case
variance and no test is possible.

## Key Observations

1. **Security scores** remained relatively consistent across cases (64.4 – 66.6)
2. **Inclusivity scores** rose from Case 1 to Case 3 (55.4 to 65.6)
3. **Claude Sonnet 4.5** gave consistently higher security scores
4. **GPT-5** gave consistently higher inclusivity scores

Observations 1 and 2 are the ones the repeated-runs study was built to test.
Both survive it — see below.

## Usage Notes

- Security evaluations used the full source code (`app.ts`)
- Inclusivity evaluations used UI screenshots from `screenshots/`
- All evaluations were run in isolated sessions to prevent context contamination
- Evaluators were instructed to reply with numeric scores only, no explanations

---

# `results_v2/` — 2026 repeated-runs study (current)

60 artifacts, 7 judges, 3 repeats, 2 tracks: **2,457 judgements, 36,855 item
scores.** Full documentation in **[results_v2/README.md](results_v2/README.md)**.

## The 2026 panel

One judge per lab, each verified to accept image input and return parseable
scores. Machine-readable roster with rejection reasons in `judge_panel.json`.

| Judge | Lab | Relative to the 2025 panel |
|-------|-----|----------------------------|
| `openai/gpt-5.6-sol` | OpenAI | succeeds GPT-5 — generator's own lab, analysed separately |
| `anthropic/claude-opus-5` | Anthropic | succeeds Claude Sonnet 4.5 |
| `google/gemini-3.6-flash` | Google | succeeds Gemini 2.5 Pro |
| `mistralai/mistral-medium-3-5` | Mistral AI | succeeds Mistral Medium 3.1 |
| `x-ai/grok-4.5` | xAI | replaces DeepSeek 3.2 |
| `qwen/qwen3.8-max` | Alibaba | added |
| `moonshotai/kimi-k3` | Moonshot AI | added |

DeepSeek was dropped because it is now text-only and cannot score a
screenshot-based rubric. Two judges were added to tighten inter-rater
reliability.

## Unit of analysis

```
item → construct (mean of 3) → judgement (mean of 5 constructs)
     → judge (mean of 3 repeats) → artifact (MEDIAN over judges) → case
```

The **artifact** is the unit, n = 10 per case — 2,457 judgements are not treated
as 2,457 independent observations.

## Case medians (1–5)

| Study | Case 1 | Case 2 | Case 3 |
|-------|--------|--------|--------|
| 1 security | 3.644 | 3.778 | 3.689 |
| 1 inclusivity | 3.289 | 3.372 | **3.944** |
| 2 security | 4.489 | 4.506 | 4.511 |
| 2 inclusivity | 3.394 | 3.389 | **4.083** |

## Primary test (Kruskal-Wallis across the three cases)

| Study | Track | H | p | ε² | Case 3 vs 1, Cliff's δ |
|-------|-------|---|---|-----|------------------------|
| 1 | security | 5.133 | 0.077 | 0.177 | −0.29 |
| 1 | inclusivity | 19.001 | **0.0001** | 0.679 | **−1.00** |
| 2 | security | 0.601 | 0.740 | 0.021 | −0.16 |
| 2 | inclusivity | 3.465 | 0.177 | 0.128 | −0.48 |
| 2, working artifacts only | inclusivity | 11.550 | **0.0031** | 0.462 | **−0.97** |

Asking for inclusivity raises inclusivity scores and does not measurably lower
security scores, in either study — replicating the 2025 observations with a real
sample. What it does cost in study 2 is **working software**: case 3 converged
4/10 against 10/10 and 10/10, and only 6/10 of its artifacts had a live client
script (χ² = 9.23, p = 0.0099). The penalty shows up in artifact health, not in
the security score.

Both variants are reported — `cross_study/report_all.txt` and
`report_working_only.txt` — because excluding broken artifacts is not neutral:
every one of them is from case 3.

Reliability after exclusions: ICC(2,k) 0.556 / 0.923 (study 1 security /
inclusivity) and 0.721 / 0.951 (study 2).

## Exclusions

- `mistralai/mistral-medium-3-5` is dropped from study 1 **security** only: it
  returned a fixed response pattern, artifact-level SD 0.008. It is a usable
  inclusivity judge in both studies.
- `openai/gpt-5.6-sol` is the generator's own lab and is reported as a separate
  stratum. It scores its own lab's output slightly *harsher* than the panel and
  reaches the same conclusions on its own, so it changes nothing either way.

Both are detected and applied by the analysis scripts, not by hand. See
[results_v2/README.md §7](results_v2/README.md) for the full rationale.

## Reproducing

From the repository root:

```bash
uv run python run_batch.py   --software <study> --runs 10 --smoke-test --flow-test
uv run python run_capture.py --software <study> --runs 10
uv run python run_judge.py   --software <study> --repeats 3
uv run python analyse.py     --software <study> --drop-degenerate
uv run python report.py                       # cross-study tables
uv run python build_workbook.py               # all_results.xlsx
```

where `<study>` is `password_recovery_health` or `mfa_enrolment_banking`.
Judged artifacts live in `../generations/<study>/<case>/<run>/`.
