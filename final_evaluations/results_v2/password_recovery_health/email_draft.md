Subject: Re-run with 10 runs per case — results in, inclusivity effect is large

Hi all,

I've re-run the experiment to address the reviewer's request for multiple runs
per condition. Summary below, details attached.

WHAT WAS DONE

- 10 independent artifacts per condition instead of 1 (30 total).
- New generator: openai/gpt-5.6-terra. GPT-4o dropped.
- No seed, so runs are genuine independent draws.
- Every artifact is now verified to actually run: 29/30 boot, 28/30 have a
  working password-recovery flow.
- Each artifact walked through its UI in a browser and screenshotted. 230
  screenshots.
- Judged by 7 models (one per lab), on both rubrics, 3 times each = 1,239
  judgements. Previously 30, done by hand.
- Original per-case rubric files used verbatim.
- Generation cost EUR ~10, judging ~EUR 75. About 3 hours total.

RESULTS

- Inclusivity improves strongly with detailed guidance. p = 0.0001, large
  effect. Cliff's delta = -1.00, meaning complete separation: every case-3
  artifact scored above every case-1 and case-2 artifact.
- Security shows no significant difference between cases (p = 0.077). So the
  inclusivity gain came at no measurable security cost.
- Merely mentioning ADHD is not enough. Case 1 vs case 2 is not significant on
  either track. The detailed guidance is what does the work.
- Mean scores: security 3.59 / 3.77 / 3.69, inclusivity 3.29 / 3.37 / 3.91.
- Biggest inclusivity gains: memory 1.93 -> 2.81, learning 3.78 -> 4.49,
  comprehension 2.82 -> 3.37.
- Case 3 also needed far more work from the pipeline: 6.5 iterations on average
  vs 2.1 and 2.3, and it was the only case that sometimes failed to converge.

NOTES / THINGS TO BE AWARE OF

- Case 3's inclusivity rubric contains ADHD guidance that case 1's does not. We
  kept the original per-case rubrics, so the instrument is matched to the
  condition. Some of the difference may be the rubric rather than the artifact.
  This needs saying in the limitations.
- I'd phrase the security finding as "no detectable security cost" rather than
  "security improved". The one significant security difference disappears once
  the generator's own lab is excluded from the panel.
- One judge (Mistral) was dropped from the security track. It returned a fixed
  response pattern rather than actually judging: 87% fives regardless of
  artifact. Excluded and documented.
- The OpenAI judge was analysed separately, since OpenAI generated the code. It
  turned out to be harsher on its own lab's output, not more lenient, and the
  bias doesn't vary by condition. So self-preference can't explain the result.
- Inclusivity judge agreement is strong (ICC 0.92). Security agreement is only
  moderate (0.56), so those numbers carry more disagreement.
- 2 of the 30 artifacts have real defects that the Evaluator LLM passed anyway.
  One never parses. In the other, a mis-escaped regex makes password recovery
  impossible for every user, while the app still looks and behaves fine on the
  surface. That one is a nice illustration for the paper.

ATTACHED

- TLDR.md - one screen
- SUMMARY.md - full method and limitations
- statistics.xlsx - all tables
- screenshots_representative.zip - one typical journey per condition. Not
  cherry-picked; each is the run closest to its own condition's median.

Happy to walk through any of it.

Best,
Janne
