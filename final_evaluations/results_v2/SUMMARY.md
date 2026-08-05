# Repeated-runs experiment: security and inclusivity in LLM-generated code

Summary of the re-run carried out in response to the reviewer's request for
multiple runs per condition. Companion file: `statistics.xlsx`.

Date: 2026-08-05 · Generation cost USD 10.56 · Judging cost USD 79.78

---

## 1. What was run

The original study produced **one** artifact per condition. Reviewers asked for
repeated runs, so the pipeline was re-run to produce **ten independent artifacts
per condition** — 30 in total.

| | Original | This re-run |
|---|---|---|
| Artifacts per case | 1 | **10** |
| Generator | GPT-4o | **`openai/gpt-5.6-terra`** (snapshot `-20260709`) |
| Judges | 5 | **7**, one per lab |
| Judgements | 30, manual | **1,239**, automated |

The three conditions are unchanged: identical security requirements (five OWASP
Top 10 2021 categories) with the inclusivity specification varied.

- **Case 1** — security only, no cognitive condition mentioned
- **Case 2** — security plus "the user has ADHD"
- **Case 3** — security plus detailed ADHD accessibility guidance

Runs are **independent draws**. No seed is set anywhere, since a fixed seed
would suppress exactly the between-run variance the design exists to measure.
Frontier reasoning models no longer expose `temperature`, so each run samples
under the provider's default configuration; `reasoning_effort` is pinned to
`medium` and recorded per run. The upstream provider is pinned, after a
validation batch was observed splitting one run across two backends.

Generation used the unchanged three-agent pipeline (Tasker → Coder → Evaluator,
max 12 iterations).

## 2. What was tested, and how

### Artifacts are verified to actually work

`PASS_MARKER` only records that the Evaluator LLM judged the code complete; it
never executes anything. Two execution-based checks were added:

- **Boot test** — the artifact is started under Bun and must serve a response.
- **Flow test** — the full recovery journey is walked over HTTP (request code →
  verify → set password → sign in → MFA → …) plus negative checks for replayed
  tokens, forged CSRF and wrong credentials.

**29/30 boot, 28/30 have a working recovery flow.** The two failures are real
defects, both approved by the Evaluator LLM (see §4).

### Screenshots

The inclusivity rubric is scored from screenshots. Each artifact was driven
through its journey in Chromium and photographed at every step — **230
screenshots** across 28 artifacts. Because every run invents its own interface,
the click-through plan is derived per artifact by a model reading the source;
Playwright then executes it and captures the images.

### Judging

Each artifact is scored by **7 judges**, on **2 tracks**, **3 times** each.

| Judge | Lab |
|---|---|
| `openai/gpt-5.6-sol` | OpenAI *(generator's lab — analysed separately)* |
| `anthropic/claude-opus-5` | Anthropic |
| `google/gemini-3.6-flash` | Google |
| `mistralai/mistral-medium-3-5` | Mistral |
| `x-ai/grok-4.5` | xAI |
| `qwen/qwen3.8-max` | Alibaba |
| `moonshotai/kimi-k3` | Moonshot AI |

DeepSeek could not be carried forward from the original panel: it is now
text-only and cannot score the screenshot-based rubric.

The **existing per-case rubric files are used verbatim**, each artifact judged
with the rubric for its own case. Security judges read `app.ts`; inclusivity
judges receive that run's screenshots. Every record stores the SHA-256 of both
the rubric and the artifact, and the artifact hash is re-checked against the
generation manifest before scoring, so an artifact cannot be scored against the
wrong rubric unnoticed.

### One rubric issue that had to be handled

Security items 2 and 3 are worded so that **agreement means the system is less
secure** ("The same reset code works for any other user"). All other items on
both rubrics are positively worded.

In the previously published results the panel split 1-vs-5 on exactly these two
items for the same artifact — four judges answered literally, one evaluatively.
That is interpretation noise, and it halves the A01 construct score.

The rubric text was left untouched. Instead the scoring protocol states that
each statement is judged literally as a factual claim, a one-sentence
justification is required per item so any mis-reading is auditable, and items 2
and 3 are reverse-scored (6 − x) at aggregation.

### Aggregation and statistics

Fixed before results were seen:

> item → construct (mean of its 3 items) → judgement (mean of 5 constructs) →
> judge (mean over 3 repeats) → artifact (**median** over judges) → case

The **artifact** is the unit of analysis, giving **n = 10 per case**, so the
tests do not treat 1,239 judgements as independent observations when they are
seven opinions about thirty things. Kruskal-Wallis across cases, Mann-Whitney
pairwise with Holm correction, ε² and Cliff's δ for effect size.

---

## 3. Results

### Detailed inclusivity guidance raises inclusivity substantially, at no detectable cost to security

| Case | Security | Inclusivity |
|---|---|---|
| 1 — no condition | 3.59 ± 0.24 | 3.29 ± 0.05 |
| 2 — ADHD mentioned | 3.77 ± 0.13 | 3.37 ± 0.11 |
| 3 — detailed guidance | 3.69 ± 0.15 | **3.91 ± 0.16** |

| Track | Kruskal-Wallis | Effect | Case 3 vs others |
|---|---|---|---|
| **Inclusivity** | H = 19.00, **p = 0.0001** | ε² = 0.68 (large) | p = 0.0008, **Cliff δ = −1.00** |
| Security | H = 5.13, p = 0.077 (n.s.) | ε² = 0.18 | no significant difference |

**Cliff's δ = −1.00 is complete separation**: every case-3 artifact scores higher
on inclusivity than every case-1 and case-2 artifact.

Security shows **no significant difference between cases**. The defensible claim
is that detailed inclusivity guidance carries **no detectable security cost** —
not that security improved.

Merely *mentioning* ADHD (case 2) is not enough: case 1 vs case 2 is not
significant on either track. The gain requires the detailed guidance.

### Where the inclusivity gain comes from

| Construct | Case 1 | Case 2 | Case 3 |
|---|---|---|---|
| Attention | 4.29 | 4.39 | 4.63 |
| **Memory** | 1.93 | 1.93 | **2.81** |
| **Comprehension** | 2.82 | 2.88 | **3.37** |
| Decision making | 3.79 | 3.88 | 4.35 |
| **Learning** | 3.78 | 3.78 | **4.49** |

Memory is the weakest construct in every condition (~1.9–2.8) — driven by
absent password-manager / autofill / "remember me" support.

Security constructs are flat across cases; A05 misconfiguration is weakest
(1.83–2.19), A03 injection strongest (4.56–4.60).

### The generator's own lab is harsher, not more lenient

The artifacts were generated by an OpenAI model, so the OpenAI judge is analysed
as a separate stratum rather than pooled into the panel.

| Track | Independent panel | Generator's lab | Bias | p |
|---|---|---|---|---|
| Security | 3.68 | 3.26 | **−0.42** | < 0.0001 |
| Inclusivity | 3.51 | 3.57 | +0.06 | 0.015 |

The bias runs opposite to the usual self-preference concern. Rank agreement with
the panel stays high (ρ = 0.68 / 0.82), so it is a severity offset rather than a
different ordering.

Crucially the bias **does not vary across the manipulation** (security p = 0.29,
inclusivity p = 0.14), so it shifts all three cases alike and cannot manufacture
the case difference. Both strata reach the same conclusion on inclusivity —
independent panel p = 0.0001 (δ = −1.00), generator's lab alone p = 0.0021
(δ = −0.93).

### Judge reliability

| Track | ICC(2,k) | Krippendorff α | Mean pairwise ρ | Within-judge SD |
|---|---|---|---|---|
| Inclusivity | **0.92** | 0.62 | 0.70 | 0.10 |
| Security | 0.56 | 0.06 | 0.50 | 0.14 |

Inclusivity agreement is strong. Security agreement is only moderate even after
excluding the judge below, so the security numbers carry real judge
disagreement.

**One panel member is not a usable security judge.**
`mistralai/mistral-medium-3-5` returns 5 to every positively-worded statement and
1 to the two reverse-worded ones, irrespective of artifact: 86.6% fives, three
distinct values across 1,350 item scores, and an artifact-level SD of **0.008**
against 0.16–0.31 for every other judge. It is a fixed response pattern, not a
judgement. On the inclusivity track the same model is the panel's *best*
discriminator (SD 0.524), so the failure is specific to reading ~25k tokens of
TypeScript. It is excluded from the security track and the exclusion is
reported, not silent. Retaining it halved security ICC (0.56 → 0.27) and drove
Krippendorff α negative.

## 4. Two artifacts carry defects the Evaluator LLM approved

- **`case_3/run_10`** — duplicate `key` declaration (a function at line 158, a
  `const` at line 806). The file never parses and the server cannot start.
  `PASS_MARKER` is present.
- **`case_1/run_09`** — the email check uses
  `/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/`: double backslashes inside a *regex
  literal* rather than a string, so the pattern demands a literal backslash in
  the address. Verified under Bun — no ordinary email matches. Password recovery
  cannot complete for any user, yet the app boots and serves a polished page, so
  only the flow test detects it.

Convergence also differed sharply: case 3 needed **6.5 iterations** on average
against 2.1 and 2.3, and was the only case to hit the 12-iteration ceiling (2 of
10 runs).

---

## 5. Limitations to state in the paper

1. **The inclusivity instrument is matched to the condition by design.** The
   per-case rubric files were used as-is; case 3's rubric additionally contains
   the ADHD description and guidance that case 1's does not. Part of the
   inclusivity difference may therefore be the rubric rather than the artifact.
   The judging is unblinded by construction and should be reported as
   instrument-matched.
2. **Security agreement is moderate** (ICC 0.56) even after excluding the
   degenerate judge.
3. **`case_3/run_10` has no inclusivity score** — it never parses, so no
   screenshots exist. Case 3 therefore has n = 9 on that track against n = 10.
4. **Flow-test results are LLM-mediated measurement**, not ground truth: the
   call sequence is model-derived, though pass/fail comes from real HTTP
   responses. Each derived plan is retained for audit.
5. **The panel changed** from the submitted version — DeepSeek is text-only and
   was replaced; Google has no stable Gemini 3.x Pro so a current-generation
   flash model was used.
6. **Pipeline parser corrections** mean these artifacts were produced by a
   slightly different scaffold than the originally submitted ones; the two sets
   are not directly comparable.

---

## 6. Files

| File | Contents |
|---|---|
| `statistics.xlsx` | All tables below, one per sheet |
| `analysis/report.txt` | Full analysis output |
| `scores_long.csv` | 18,585 rows — one per item score, with justifications |
| `scores_artifact.csv` | 1,239 rows — one per judgement, construct means |
| `analysis/artifact_scores.csv` | 59 rows — the unit of analysis (30 artifacts × 2 tracks, less the one unscoreable) |
| `analysis/case_summary.csv` | Case × track means |
| `analysis/case_comparisons.csv` | Statistical tests |
| `analysis/self_preference.csv` | Generator-lab bias |
| `analysis/reliability.csv` | ICC, α, Spearman |
| `analysis/constructs_*.csv` | Construct breakdowns |

Reproduce with:

```bash
uv run python run_batch.py   --runs 10 --smoke-test --flow-test   # generation
uv run python run_capture.py --runs 10                            # screenshots
uv run python run_judge.py   --repeats 3                          # judging
uv run python analyse.py     --drop-degenerate                    # statistics
```
