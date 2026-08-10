# TL;DR — repeated-runs re-analysis

Reviewers asked for multiple runs per condition. We re-ran the experiment with
**10 independent artifacts per condition (30 total)** instead of one, generated
with `openai/gpt-5.6-terra`, and scored each by a **7-model judge panel, twice
over (security and inclusivity), three times each — 1,239 judgements**.

**Result: detailed inclusivity guidance improves inclusivity a lot, and costs
nothing in security.**

| Case (identical security requirements) | Security | Inclusivity |
|---|---|---|
| 1 — no cognitive condition mentioned | 3.59 | 3.29 |
| 2 — "the user has ADHD" | 3.77 | 3.37 |
| 3 — detailed ADHD guidance | 3.69 | **3.91** |

- **Inclusivity**: p = 0.0001, large effect. Cliff's δ = **−1.00** — *complete
  separation*: every case-3 artifact scores above every case-1 and case-2
  artifact.
- **Security**: p = 0.077, not significant. No detectable cost to adding
  inclusivity guidance.
- **Mentioning ADHD is not enough.** Case 1 vs case 2 is not significant on
  either track; the gain needs the detailed guidance.

Biggest gains are in **memory** (1.93 → 2.81), **learning** (3.78 → 4.49) and
**comprehension** (2.82 → 3.37).

**Three things worth knowing before quoting the numbers:**

1. Case 3's inclusivity rubric contains ADHD guidance that case 1's does not
   (we kept the original per-case rubrics), so the instrument is matched to the
   condition — part of the difference may be the rubric, not the artifact.
2. One judge (Mistral) was excluded from the security track: it returned a fixed
   response pattern rather than judging. Documented, not silent.
3. The generator's own lab (OpenAI) was analysed separately. It scored its own
   lab's output *harsher*, not more leniently, and the bias doesn't vary by
   condition — so self-preference can't explain the result.

**Also:** 2 of 30 artifacts carry defects the Evaluator LLM approved — one that
never parses, and one where a mis-escaped regex silently makes password recovery
impossible for every user while the app still looks fine. And case 3 needed
**6.5 pipeline iterations on average vs 2.1 and 2.3** — inclusivity is
substantially more work to satisfy.

**Attached:** `SUMMARY.md` (full method + limitations) · `statistics.xlsx` (all
tables) · `screenshots_representative.zip` (one typical journey per condition).
