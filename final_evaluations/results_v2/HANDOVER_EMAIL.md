Subject: Full evaluation data — two user stories, 60 artifacts, 2,457 LLM judgements

Hi all,

Attached is `results_v2.zip` — the complete evaluation dataset for the revision.
It replaces the single-run data in the submitted version. Everything below is
also written up inside the zip, so you don't need this email to make sense of it.

WHERE TO START

1. `README.md` at the top of the zip. Standalone, ~10 minutes, explains the
   design, the judges, every exclusion, and how each number is computed.
2. `cross_study/all_results.xlsx` — 21 sheets, every table in one file. The
   first sheet is a plain-language guide to the rest.
3. `cross_study/report_all.txt` — the same tables as plain text, in the order
   you'd read them.

If you only look at one thing, make it sheet `03_case_medians` in the workbook.

WHAT WAS DONE

- Two user stories, not one. Story 1 is the original password recovery for a
  health portal (ADHD). Story 2 is new: MFA enrolment for online banking
  (dyslexia). Different domain, different condition, deliberately identical
  prompt structure so nobody can attribute a difference to wording style.
- Three cases per story, varying only the inclusivity specification: none /
  condition named / condition described with requirements.
- 10 independent runs per case instead of 1. 60 artifacts total.
- Generator: openai/gpt-5.6-terra, same model for all three pipeline agents.
  No seed, so the runs are genuine independent draws.
- Every artifact was booted, probed, and walked through its own UI in a real
  browser. 509 screenshots.
- Judged by 7 models, one per lab, on both rubrics, 3 times each.
  2,457 judgements, 36,855 individual item scores. Previously 30, by hand.
- The original per-case rubric files were used verbatim, so the instrument is
  unchanged from the submitted version.
- Roughly $50 of generation and $160 of judging.

WHAT THE NUMBERS SHOW

Case medians, on the 1-5 scale:

                  case 1   case 2   case 3
  S1 security      3.64     3.78     3.69
  S1 inclusivity   3.29     3.37     3.94
  S2 security      4.49     4.51     4.51
  S2 inclusivity   3.39     3.39     4.08

- Detailed inclusivity guidance raises inclusivity scores, in both stories.
  Story 1: p = 0.0001, Cliff's delta = -1.00, complete separation — every case-3
  artifact scored above every case-1 and case-2 artifact.
  Story 2: p = 0.003 over the artifacts that actually work, delta = -0.97.
- Merely naming the condition does nothing. Case 1 vs case 2 is not significant
  on either track in either story. The detailed guidance is what does the work.
- No measurable security cost. Security is flat across the cases in both
  stories (p = 0.077 and p = 0.740).
- But in story 2 there IS a cost, and it is not in the score. Case 3 converged
  4/10 against 10/10 and 10/10, and only 6/10 of its artifacts had a working
  client script (chi-squared p = 0.0099). Asking for accessibility made the
  model much more likely to ship something broken. This is the most interesting
  new finding and it replicates the weaker signal in story 1.
- Story 2's artifacts score much higher on security than story 1's — 0.75 to
  0.89 higher in every case, near-complete separation. Same rubric, so this is a
  real comparison. Likely the requirements: MFA enrolment names its controls
  more concretely than password recovery does.

HOW TO READ IT WITHOUT GETTING BURNED

- Two report variants exist for a reason. `report_all.txt` scores every artifact
  as judged. `report_working_only.txt` excludes two story-2 artifacts whose
  client script is dead. The exclusion is not neutral — both are from case 3,
  because case 3 is the only case that produced any. Please report both, never
  the filtered one alone.
- Security constructs are identical across the two stories and comparable.
  Inclusivity constructs are NOT — the stories target different conditions and
  their rubrics name different dimensions. Compare inclusivity between stories
  at the overall-score level only.
- The unit of analysis is the artifact, n = 10 per case. The 2,457 judgements
  are seven opinions about sixty things, not 2,457 observations. Please don't
  run tests on the row counts in `scores_long.csv`.
- Case 3's rubric contains condition guidance that case 1's does not. We kept
  the original per-case rubrics, so the instrument is matched to the condition.
  Part of the inclusivity difference may be the rubric rather than the artifact.
  This needs to be in the limitations.
- One judge (Mistral) is dropped from story 1's security track only. It returned
  a fixed response pattern rather than a judgement — 87% fives regardless of
  artifact, artifact-level SD 0.008. Documented, and the scripts detect it
  automatically rather than by hand.
- The OpenAI judge is reported as a separate stratum, since OpenAI generated the
  code. It turns out to be harsher on its own lab's output, not more lenient,
  and on its own it reaches the same conclusions. Self-preference does not
  explain anything here.
- Inclusivity judge agreement is strong (ICC 0.92 and 0.95). Security agreement
  is only moderate (0.56 and 0.72), so the security numbers carry more
  disagreement and deserve more hedging in the text.
- Three artifacts across the two stories have defects that the Evaluator LLM
  passed anyway: one duplicate object key, one over-escaped regex that makes
  recovery impossible for every user while the app still looks fine, and one
  outright syntax error. Good illustrations for the paper.

WHAT IS IN THE ZIP

  README.md                        read this first
  <story>/security|inclusivity/    every individual judgement as JSON, with the
                                   score, a one-sentence justification per item,
                                   and hashes of the rubric and the code judged
  <story>/scores_long.csv          one row per item score, ~18,500 rows each
  <story>/scores_artifact.csv      one row per judgement
  <story>/analysis/                per-story tables and full analysis output
  cross_study/                     combined tables, both report variants,
                                   all_results.xlsx
  HANDOVER_EMAIL.md                this message

NOT in the zip: the generated applications themselves and the 509 screenshots.
They're another 74 MB and live in `generations/` in the repo — say the word and
I'll send those too. Every judgement record carries the SHA-256 of the code it
scored, so they can be tied back exactly.

Every script that produced these numbers is in the repo and documented in the
root README. `analyse.py`, `report.py` and `build_workbook.py` regenerate every
table from the raw records with no API calls.

Happy to walk through any of it.

Best,
Janne
