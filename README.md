# Experimental Dataset: Security and Inclusivity in LLM-Generated Code

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.XXXXXXX-blue)](https://doi.org/10.5281/zenodo.XXXXXXX)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

Complete experimental dataset, pipeline and replication materials for evaluating
security and inclusivity in Large Language Model (LLM)-generated authentication
code.

**The question.** If you ask an LLM to make code accessible to a user with a
cognitive condition, does the security of that code suffer?

**Two collections of data, gathered a year apart.**

| | `final_evaluations/results/` | `final_evaluations/results_v2/` |
|---|---|---|
| Collected | Sep 2025 – Feb 2026 | Aug 2026 |
| Design | 1 generation per case | **10 generations per case** |
| User stories | 1 | **2** |
| Artifacts | 3 | **60** |
| LLM judges | 5, scored once, by hand | **7, scored 3× each, scripted** |
| Judgements | 30 | **2,457** |
| Status | archival — as submitted | **current — use for the revision** |

The second collection exists because reviewers pointed out, correctly, that a
single generation per case cannot separate a real effect from run-to-run
variance. It is not a correction of the first; it is a larger, independent
experiment. **Do not pool them** — different generator, different judge panel,
different aggregation.

> `results_v2/` carries its own complete, standalone documentation:
> **[final_evaluations/results_v2/README.md](final_evaluations/results_v2/README.md)**.
> Anyone analysing the 2026 data should start there.

## Where to start

| If you are… | Start here |
|---|---|
| reviewing the paper | [Headline Findings](#headline-findings), then `final_evaluations/results_v2/cross_study/report_all.txt` |
| re-analysing the data | [`final_evaluations/results_v2/README.md`](final_evaluations/results_v2/README.md) — standalone, needs nothing else |
| reproducing the experiment | [Replicating the Experiment](#replicating-the-experiment) |
| looking at what the model built | [`best_run_screenshots/`](best_run_screenshots/), or run one artifact — see [Quick Start](#quick-start) |
| running the human evaluation | [`human_evaluation_package/README.md`](human_evaluation_package/README.md) |
| citing or archiving this | [PUBLISHING.md](PUBLISHING.md) |

Every number in the paper is regenerated from the raw records by
`report.py` and `build_workbook.py`; no figure is transcribed by hand.

## Related Publication

TBA

## Table of Contents

- [Experimental Design](#experimental-design)
- [Headline Findings](#headline-findings)
- [Repository Structure](#repository-structure)
- [How the Data Was Gathered](#how-the-data-was-gathered)
- [Quick Start](#quick-start)
- [Replicating the Experiment](#replicating-the-experiment)
- [Instrumentation and Threats to Validity](#instrumentation-and-threats-to-validity)
- [Verifying Generated Artifacts](#verifying-generated-artifacts)
- [Evaluation Data](#evaluation-data)
- [Human Evaluation](#human-evaluation)
- [Software Dependencies](#software-dependencies)
- [Citation](#citation)
- [License](#license)

## Experimental Design

Two **user stories**. Each holds its functional goal and its security
requirements fixed, and varies **only** the inclusivity specification across
three **cases**:

| Case | Inclusivity specification |
|------|---------------------------|
| **Case 1** | None. Functional goal and security requirements only. |
| **Case 2** | Condition named, nothing more. |
| **Case 3** | Condition described, plus concrete inclusivity requirements. |

| Story | Application | Cognitive condition | Requirements |
|-------|-------------|--------------------|--------------|
| 1 | Password recovery, health portal | ADHD | `requirements/password_recovery_health/` |
| 2 | MFA enrolment, online banking | Dyslexia | `requirements/mfa_enrolment_banking/` |

Story 2 was added for the revision. Its requirement documents follow story 1's
structure section by section — same purpose paragraph, same use-case format,
same five OWASP headings, same deliverables — so a difference between the
stories cannot be attributed to prompt style.

Both stories share identical security requirements structure, based on five
OWASP Top 10 (2021) categories: A01 Broken Access Control, A02 Cryptographic
Failures, A03 Injection, A05 Security Misconfiguration, A07 Identification and
Authentication Failures.

The six input documents — the only thing that differs between conditions:

| File | Story | Case | Lines |
|---|---|---|---|
| `password_recovery_health_no_inclusivity_no_condition.md` | 1 | 1 | 48 |
| `password_recovery_health_no_inclusivity.md` | 1 | 2 | 48 |
| `password_recovery_health_with_inclusivity.md` | 1 | 3 | 60 |
| `mfa_enrolment_banking_no_inclusivity_no_condition.md` | 2 | 1 | 41 |
| `mfa_enrolment_banking_no_inclusivity.md` | 2 | 2 | 41 |
| `mfa_enrolment_banking_with_inclusivity.md` | 2 | 3 | 54 |

Case 1 and case 2 are the same length within each story: case 2 adds only the
name of the condition, inline. Case 3 adds a description of the condition and
concrete inclusivity requirements. The file names are historical — "no
inclusivity" distinguishes cases 1 and 2 from case 3, and "no condition"
distinguishes case 1 from case 2.

## Headline Findings

From the 2026 repeated-runs collection. Case medians, artifact score on a 1–5
scale:

| | Case 1 | Case 2 | Case 3 |
|---|---|---|---|
| Story 1 security | 3.644 | 3.778 | 3.689 |
| Story 1 inclusivity | 3.289 | 3.372 | **3.944** |
| Story 2 security | 4.489 | 4.506 | 4.511 |
| Story 2 inclusivity | 3.394 | 3.389 | **4.083** |

1. **Detailed inclusivity guidance raises inclusivity scores, in both stories.**
   Story 1: *p* = 0.0001, Cliff's δ = −1.00 — complete separation, every case-3
   artifact above every case-1 and case-2 artifact. Story 2: *p* = 0.003,
   δ = −0.97 over the artifacts that actually work.
2. **Naming the condition alone does nothing.** Case 1 vs case 2 is not
   significant on either track in either story.
3. **No measurable security cost.** Security is flat across cases in both
   stories (*p* = 0.077 and *p* = 0.740).
4. **But there is a cost, and it is not in the score.** In story 2, case 3
   converged 4/10 against 10/10 and 10/10, and only 6/10 of its artifacts had a
   working client script (χ² = 9.23, *p* = 0.0099). Asking for accessibility
   made the model markedly more likely to ship something broken. Story 1 shows
   the same signal more weakly (8/10 convergence in case 3).

Full statistics, effect sizes, reliability and every exclusion:
[`final_evaluations/results_v2/README.md`](final_evaluations/results_v2/README.md).

## Repository Structure

```
.
├── requirements/                        INPUT: the action prompts
│   ├── password_recovery_health/        story 1, cases 1–3
│   └── mfa_enrolment_banking/           story 2, cases 1–3
│
├── software_descriptions/               narrative specification per story
│   ├── password_recovery.md
│   └── mfa_enrolment.md
│
├── prompts/                             PIPELINE: agent system prompts
│   ├── prompt_tasker.txt                requirement decomposition
│   ├── prompt_coder.txt                 code generation
│   ├── prompt_evaluator.txt             functional completeness check
│   ├── prompt_inclusivity_eval.txt      inclusivity scoring prompt
│   └── prompt_programmer_hitl.txt       single-agent human-in-the-loop mode
│
├── run_batch.py                         STAGE 1: batch generation
├── run_capture.py                       STAGE 2: browser walkthrough + screenshots
├── run_judge.py                         STAGE 3: LLM judging
├── analyse.py                           STAGE 4: per-study statistics
├── report.py                            STAGE 4: cross-study tables
├── build_workbook.py                    STAGE 4: bundle into all_results.xlsx
├── run.py                               single generation, no batch
│
├── generations/                         OUTPUT: the 2026 artifacts (60 runs)
│   └── <story>/
│       ├── batch_manifest.json          model, snapshot, cost, hashes, per run
│       ├── capture_summary.json         screenshot counts per run
│       └── <case>/run_NN/
│           ├── app.ts                   the artifact
│           ├── screenshots/             what the inclusivity judges saw
│           ├── code_iter*.tsx           every iteration, kept
│           ├── tasker_report_iter*.md   task decomposition per iteration
│           ├── evaluator_report_iter*.md
│           ├── smoke.json               boot, serve, client-script health
│           ├── flow.json, flow_spec.json  functional flow test + its plan
│           ├── capture.json             the walkthrough actually executed
│           ├── ui_script.json           the walkthrough derived for this artifact
│           ├── log.jsonl, state.jsonl   full generation trace
│           ├── tokens_summary.json      tokens and cost
│           └── PASS_MARKER              Evaluator agent accepted the artifact
│
├── final_evaluations/                   EVALUATION
│   ├── README.md                        the two result sets, explained
│   ├── judge_panel.json                 2026 panel + rejected candidates
│   ├── evaluation_rubrics/
│   │   ├── {security,inclusivity}_eval_case_{1,2,3}.md      story 1
│   │   └── mfa_enrolment_banking/…                          story 2
│   ├── results/                         2025 single-run scores (archival)
│   └── results_v2/                      2026 repeated-runs data (current)
│       ├── README.md                    ← standalone analysis guide
│       ├── HANDOVER_EMAIL.md            cover note for collaborators
│       ├── password_recovery_health/    judgements, CSVs, analysis/
│       ├── mfa_enrolment_banking/       judgements, CSVs, analysis/
│       └── cross_study/                 combined tables, all_results.xlsx
│
├── best_run_screenshots/                the 6 best artifacts, step by step,
│                                        for sharing without running anything
│
├── human_evaluation_package/            HUMAN EVAL: the 6 best artifacts
│   ├── source_code/                     for the security experts to read
│   ├── source_code_blinded/             same six, unlabelled, + separate key
│   └── deploy_cloudflare/               for the inclusivity experts to click
│
├── workspace/                           2025 artifacts (archival)
│   └── password_recovery_health/<case>/legacy_single_run_gpt4o/
├── screenshots/                         2025 screenshots (archival)
│
├── human_evaluations/                   2025 expert assessment results
├── survey_questionnaires/               the PDF instruments used
├── PUBLISHING.md                        how this repo is archived to Zenodo
│
└── app/                                 pipeline implementation
    ├── cli.py, constants.py
    ├── pipeline/multi.py                Tasker → Coder → Evaluator loop
    ├── pipeline/single.py               human-in-the-loop mode
    └── utils/
        ├── parsing.py                   NEW_TASKS / DECISION parsers
        ├── smoke.py                     boot, probe, client-script health
        ├── flow.py                      LLM-derived HTTP flow test
        ├── capture.py                   LLM-derived Playwright walkthrough
        ├── judge.py                     rubric loading, scoring, validation
        ├── io.py, tokens.py, pricing.py, summary.py
```

## How the Data Was Gathered

Four stages. Each writes files the next reads; nothing is passed by hand.

```
requirements/          run_batch.py       run_capture.py      run_judge.py        analyse.py
   ┌──────┐            ┌──────────┐       ┌──────────┐        ┌─────────┐        report.py
   │ case │──────────► │ generate │─────► │ walk the │──────► │  judge  │──────► ┌────────┐
   │ 1/2/3│  ×10 runs  │  + verify│       │ UI, shoot│        │ 7 × 2 × 3│       │ tables │
   └──────┘            └──────────┘       └──────────┘        └─────────┘        └────────┘
                       app.ts             screenshots/        repeat_N.json      *.csv, *.xlsx
                       smoke.json         capture.json        scores_long.csv    report_*.txt
                       flow.json
```

### Stage 1 — Generation (`run_batch.py`)

Ten independent generations per case, each in its own subprocess. A single run
is the three-agent loop in `app/pipeline/multi.py`: a **Tasker** decomposes the
requirements into tasks, a **Coder** writes one self-contained `app.ts`, and an
**Evaluator** judges functional completeness and either passes it or returns new
tasks. Up to 12 iterations. All three agents use the same model.

The batch writes `generations/<story>/batch_manifest.json`, recording per run:
model, the exact dated snapshot the provider served, resolved upstream provider,
sampling configuration, iteration count, convergence, tokens including reasoning
tokens, cost from the provider's usage accounting, `app.ts` SHA-256, and the
verification results. That manifest is the input to every later stage.

### Stage 2 — Verification and capture (`--smoke-test`, `--flow-test`, `run_capture.py`)

Generation always finishes and `app.ts` is written **before** any verification
runs; nothing from a test feeds back into the model. Three levels:

| Level | What it establishes |
|---|---|
| **Smoke** | The artifact boots under Bun, answers `GET /`, and its client script executes without throwing (`client_ok`, `page_errors`) |
| **Flow** | The whole journey works over real HTTP — request, verify, set, sign in, MFA — plus negative checks |
| **Capture** | The artifact is walked through its own UI in Chromium at a mobile viewport and photographed at each step |

509 screenshots in total. Capture completed the whole journey for 28 of story
1's 30 artifacts (1 partial, 1 failed) and 24 of story 2's (4 partial, 2
failed); counts per run are in `capture_summary.json`.

The client-script check exists because of a failure mode the first two levels
miss entirely: the browser JavaScript lives inside a template string that Bun
never parses, so an artifact with a syntax error in it still compiles, boots,
and serves HTTP 200 — while rendering a dead page. Three artifacts across the
two stories are exactly this, and all three had been accepted by the Evaluator
agent.

### Stage 3 — Judging (`run_judge.py`)

Every artifact is scored by every judge on both tracks, three times:

```
30 artifacts × 2 tracks × 7 judges × 3 repeats = 1,260 judgements per story
```

Security judges receive the `app.ts` source. Inclusivity judges receive that
run's screenshots as images. Each artifact is scored with the rubric **for its
own case**, taken verbatim from `final_evaluations/evaluation_rubrics/`.

Each judgement is written to a path that encodes its identity, so two records
can never collide:

```
final_evaluations/results_v2/<story>/<track>/<case>/<run>/<judge>/repeat_N.json
```

Every record embeds the SHA-256 of both the rubric used and the artifact scored,
and the artifact hash is checked against the manifest **before** any API call —
an artifact that does not match is refused rather than silently scored. Judging
is resumable: only readable successes and permanently unscoreable cells count as
done, so an interrupted batch retries its errors rather than baking them in.

### Stage 4 — Analysis (`analyse.py`, `report.py`, `build_workbook.py`)

Aggregation order, fixed before any result was seen:

```
item → construct (mean of 3) → judgement (mean of 5 constructs)
     → judge (mean of 3 repeats) → artifact (MEDIAN over judges) → case
```

The **artifact** is the unit of analysis, n = 10 per case — the 2,457 judgements
are seven opinions about sixty things, not 2,457 independent observations.
Kruskal-Wallis across cases, pairwise Mann-Whitney with Holm correction, ε² and
Cliff's δ for effect size, ICC(2,k) and Krippendorff's α for reliability.

## Quick Start

```bash
git clone https://github.com/[organization]/paper_llm_for_secure_inclusive_auth.git
cd paper_llm_for_secure_inclusive_auth

# The current results — start here
open final_evaluations/results_v2/README.md
open final_evaluations/results_v2/cross_study/all_results.xlsx

# The generated artifacts
ls generations/mfa_enrolment_banking/case_3_multi_condition_with_inclusion/

# The prompts that produced them
ls requirements/
```

### Running a generated application

The artifacts are single-file Bun applications:

```bash
# Install Bun
curl -fsSL https://bun.sh/install | bash

# TLS certificates (the artifacts expect certs/cert.pem and certs/key.pem)
brew install mkcert                       # macOS
mkcert -install
mkdir -p certs && mkcert -key-file certs/key.pem -cert-file certs/cert.pem \
  localhost 127.0.0.1 ::1

cd generations/mfa_enrolment_banking/case_3_multi_condition_with_inclusion/run_01
bun app.ts
# then open the URL it prints (https://localhost:3000 in most runs)
```

Ports are chosen by the artifact, not by us, and vary between runs — check the
`port` field in that run's `smoke.json` if nothing is printed.

## Replicating the Experiment

### Prerequisites

- Python ≥ 3.13
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- [Bun](https://bun.sh/) for running the artifacts
- An OpenRouter API key (or OpenAI / Anthropic)
- Chromium via Playwright, for capture: `uv run playwright install chromium`

### Installation

```bash
pip install uv
uv venv && source .venv/bin/activate
uv sync
cp .env.example .env      # then add your key
```

```env
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=openai/gpt-5.6-terra
OPENROUTER_PROVIDER_ORDER=openai
```

### The full pipeline

`<story>` is `password_recovery_health` or `mfa_enrolment_banking`.

```bash
# 1. generate 10 runs per case, with liveness and functional verification
uv run python run_batch.py --software <story> --runs 10 --concurrency 6 \
  --max-iters 12 --model openai/gpt-5.6-terra --reasoning-effort medium \
  --smoke-test --flow-test

# 2. walk each artifact through its UI and screenshot it
uv run python run_capture.py --software <story> --runs 10

# 3. judge everything: 7 judges × 2 tracks × 3 repeats
uv run python run_judge.py --software <story> --repeats 3

# 4. statistics
uv run python analyse.py --software <story> --drop-degenerate
uv run python report.py                 # cross-study tables, both variants
uv run python build_workbook.py         # all_results.xlsx
```

Useful flags:

| Flag | Stage | Effect |
|---|---|---|
| `--dry-run` | 1, 2, 3 | list the planned work and stop |
| `--cases`, `--runs`, `--run-start` | 1, 2, 3 | restrict or extend the batch |
| `--force` | 1, 2, 3 | redo work already recorded as done |
| `--judges`, `--tracks` | 3 | restrict the panel or the rubric |
| `--tables-only` | 3 | rebuild the CSVs from existing records, no API calls |
| `--working-only` | 4 | exclude artifacts with a known-dead client script |
| `--keep-degenerate` | 4 | retain a judge that failed the discrimination check |
| `--pool-generator-lab` | 4 | fold the OpenAI judge back into the main panel |

Every stage skips work already completed, so an interrupted run can simply be
re-invoked.

### Single generation

```bash
uv run python run.py --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/mfa_enrolment_banking/mfa_enrolment_banking_with_inclusivity.md \
  --output /tmp/one_run \
  --max-iters 12 --smoke-test --verbose
```

### Pipeline Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| LLM Provider | OpenRouter | API aggregation service |
| Code generation model | `openai/gpt-5.6-terra` | Same model for Tasker, Coder and Evaluator, across all cases and both stories |
| Model snapshot | `…-20260709` | Recorded per run, not just the alias |
| Temperature | not client-exposed | Model samples at a fixed internal temperature; see below |
| Reasoning effort | `medium` | Recorded experimental parameter |
| Seed | none | Deliberately unset, to preserve between-run variance |
| Runs per case | 10 | Independent draws |
| Maximum iterations | 12 | Upper bound for convergence |
| Judge panel | 7 models, one per lab | See `final_evaluations/judge_panel.json` |
| Repeats per judgement | 3 | Within-judge variance is measured, not assumed away |

#### Pinning the upstream provider

OpenRouter may serve one model id from several upstream backends. In a
validation batch, 11 of 12 calls in one run went to OpenAI and 1 to Azure.
Because different backends can differ in serving configuration, pin routing
before a real batch with `OPENROUTER_PROVIDER_ORDER=openai`. This sets
`allow_fallbacks: false`; transient failures are absorbed by the retry logic in
`app/utils/io.py` rather than by silently switching backend. The provider
actually used is recorded per run either way.

#### Sampling configuration

Runs are **independent draws**: no seed is ever sent, since a fixed seed would
suppress the between-run variance the design exists to measure.

Frontier reasoning models — the entire GPT-5.x family, Claude Sonnet 5 — do
**not** expose `temperature`; they sample at a fixed internal temperature.
`provider.py` queries each model's `supported_parameters` and sends
`temperature` only when the model accepts it, recording the effective setting
per run. With `openai/gpt-5.6-terra` the reported configuration is therefore
`temperature: null, temperature_supported: false`, and repeated runs vary
through the model's own sampling rather than a client-set parameter.

`reasoning_effort` **is** exposed, and materially affects both output quality
and token cost, so it is treated as a recorded experimental parameter (default
`medium`). If an explicitly set temperature is required, use a frontier model
that exposes one — `x-ai/grok-4.5`, `google/gemini-3.6-flash` and
`qwen/qwen3.8-max` all do — and pass `--temperature`.

#### Convergence

A run that reaches `--max-iters` without a PASS verdict writes a
`NO_CONVERGENCE` marker and is recorded with `converged: false`. Such runs are
reported rather than discarded: convergence rate is itself a per-case outcome,
and in story 2 it is one of the more interesting ones.

### Cost and runtime

| Stage | Story 1 | Story 2 |
|---|---|---|
| Generation | $10.56 | $22.36 (≈$39 including a discarded batch and a pilot) |
| Judging | $79.78 | $79.66 |

Costs are taken from the provider's usage accounting, not estimated from token
counts. Generation runs at `--concurrency 6`; capture and smoke testing are
serialised, because artifacts bind fixed ports.

## Instrumentation and Threats to Validity

The pipeline is a scaffold, not a neutral observer, so it is worth being
explicit about where the harness can influence the result. Generation is always
finished and `app.ts` written **before** any verification runs — nothing from
the smoke, flow or capture stage feeds back into the model — but the generation
loop itself is apparatus.

**Affects what is generated.** The `NEW_TASKS` and `DECISION` parser corrections
below change what the Coder is told to do and when a run stops, so they change
the artifacts. There is no "unscaffolded model" baseline to compare against: the
earlier parser was equally an intervention, just an undocumented and lossy one
that discarded part of the Evaluator's instructions. `reasoning_effort` and the
900s timeout likewise shape output — the latter by no longer selecting against
runs that generate a lot of text. All are held constant across cases and across
both stories, so they do not confound the comparisons, but they do define what
is being measured and are recorded per run.

**Must not hide model failures.** Non-working output is a result, so the harness
is built to record rather than rescue:

| Mechanism | Policy |
|---|---|
| Tasker emits unparseable JSON | One corrective re-ask, but every occurrence is counted in `protocol_violations`; an unrecoverable case writes `PROTOCOL_VIOLATION_*` and fails the run |
| Run fails mid-generation | Cause is classified; **only positively identified infrastructure faults** (timeout, 429, 5xx, connection error) are retried. Model and unknown causes are kept as recorded failures |
| Configuration fault (bad key, unknown model id) | Aborts the whole batch, rather than recording dozens of "failures" that say nothing about the model |
| Previous failed attempt | Preserved as `run_NN_failed_attempt_N/`, never deleted |
| Run hits `--max-iters` | Recorded as `converged: false` with a `NO_CONVERGENCE` marker, and reported |
| Artifact fails to boot | Recorded; a clash with an unrelated host process is reported as `port_conflict`, distinct from a defect |
| Artifact boots but its client script dies | Recorded in `smoke.json` as `client_ok: false` with the page errors, and the artifact is still judged |
| Capture stalls part-way | The screenshots taken so far are kept and the run is marked partial, so a broken journey stays visible |

The smoke test supplies free ports via `PORT`/`HTTPS_PORT`/`HTTP_PORT` so
artifacts are not failed for colliding with unrelated local services. This is
charitable to the artifact, so `smoke.json` records `port_hints` and
`used_hint_port`, making visible the cases where env configuration rather than
the artifact itself avoided a clash.

Batch-level counters (`runs_failed`, `failures_by_cause`, `retried_runs`,
`tasker_json_parse_failures`) are aggregated in the manifest so any rescue the
harness performed is visible in the reported results.

**Broken artifacts are judged, not removed.** Every artifact that produced
screenshots was scored, including ones that do not work. The reports are
published in two variants — all artifacts, and working artifacts only — because
excluding the broken ones is not neutral: they are concentrated in case 3, which
is itself part of the finding.

**Measurement error.** The flow test is LLM-mediated: a badly derived plan can
fail a working artifact, and a weak plan can pass a broken one. Its error rate
is not quantified, so flow results are instrument readings rather than ground
truth, and they never enter any score or statistic. Each run's derived plan is
kept in `flow_spec.json` for audit. During development, four executor defects
each produced confidently wrong verdicts caught only by manual inspection — at
batch scale, some misclassification should be assumed.

**The verification instruments differ between the two stories.** Story 1 was
frozen before story 2 was designed, and predates the client-script check, the
browser-exploration walkthrough and the TOTP-aware flow client. Boot statistics,
flow pass rates and screenshot counts are therefore **not** comparable across
stories. The judgement scores are: same rubrics, same panel, same protocol.

### Changes to the Pipeline

The generation loop was hardened for unattended batch execution. Two changes
alter behaviour relative to the pipeline that produced the 2025 single-run
artifacts, and are noted here for transparency:

1. **`NEW_TASKS` parsing.** The original parser accepted only `-`, `1.`, `2.`
   and `3.` line prefixes and stopped at the first blank line, so tasks numbered
   4 and above were silently dropped and hierarchical task lists were flattened
   into a mixture of headings and sub-details. The parser in
   `app/utils/parsing.py` reads every outermost item and folds nested detail
   into its parent task.
2. **`DECISION` parsing.** The original required a line beginning literally with
   `DECISION` and fell back to `FAIL` otherwise, so a model writing
   `**DECISION:** PASS` would be forced to run to `--max-iters`. Markdown
   emphasis and heading markers are now tolerated.

Supporting changes without behavioural effect on a successful run: request
timeout raised from 60s to 900s (reasoning models routinely exceed 60s),
transient API failures retried with exponential backoff, Tasker JSON tolerant of
code fences with one corrective retry, reasoning tokens counted, cost taken from
OpenRouter usage accounting, and per-run artifacts always overwritten rather
than skipped when present.

## Verifying Generated Artifacts

`PASS_MARKER` records only that the Evaluator LLM judged the code complete; it
does not execute anything. Three levels of execution-based verification are
available.

**`--smoke-test` (liveness).** Boots the artifact under Bun and checks that it
answers `GET /`. Result in `run_NN/smoke.json`. Listening ports are read from
the OS for the child process, because generated apps declare ports through
variables, read non-standard env names (`PORT`, `HTTPS_PORT`, `HTTP_PORT` have
all been observed) and may log nothing on startup. Both loopback families are
probed — some artifacts bind `::1` only. Boot-and-probe is serialised by a file
lock across processes: artifacts hardcode ports such as 443, 80 and 3000, so
concurrent smoke tests otherwise report working artifacts as broken. A port
already held by another host process is reported as `port_conflict`, distinct
from a defect in the artifact.

The same stage loads the served page in Chromium at a mobile viewport and
records `client_ok`, `page_errors` and `interactive_elements`. This is what
catches the failure mode described earlier: client JavaScript inside a template
string that Bun never parses, so a syntax error there produces an app that
compiles, boots and serves 200 while rendering nothing.

**`--flow-test` (functional).** Walks the whole journey over real HTTP — for
story 1 request code, verify, set password, sign in, MFA; for story 2 sign in,
identity verification, authenticator provisioning, TOTP verification, backup
codes — plus negative checks such as replayed tokens and forged CSRF. Results in
`run_NN/flow.json`, with the derived plan preserved in `run_NN/flow_spec.json`.

The call sequence has to be derived per artifact, because every run invents its
own API. Two runs of the *same* case with the *same* prompt have produced 7
granular routes with a `X-CSRF-Token` header and a single endpoint with six
server-rendered forms carrying CSRF in the JSON body. A hardcoded probe would
therefore pass on one run and fail on the next for reasons unrelated to artifact
quality. An LLM reads `app.ts` and emits the call sequence; it never judges the
outcome. **Pass/fail comes solely from executing real HTTP requests against the
running server.** The client is browser-faithful — correct `Host`, `Origin` and
`Referer` headers, CSRF offered in every common transport — because artifacts
correctly reject requests that are not.

`ok` reflects the happy path only. Negative checks are reported alongside but do
not veto it, since they are model-authored and can be poorly chosen — asserting
rejection on a route that deliberately returns a uniform response to prevent
account enumeration, for example, where the uniform reply is correct behaviour.
When the happy path fails, every request fails and the negatives pass for the
wrong reason; `negatives_meaningful` in `flow.json` flags exactly that.

**`run_capture.py` (walkthrough).** Drives the artifact through its own UI in
Chromium and photographs each step, producing the images the inclusivity rubric
is scored from. The walkthrough is derived per artifact from a DOM inventory,
for the same reason the flow plan is. Capture is serialised, since artifacts
bind fixed ports. Artifacts that stall part-way keep the screenshots taken up to
that point and are recorded as partial rather than dropped.

## Evaluation Data

### `final_evaluations/results_v2/` — current

60 artifacts, 7 judges, 2 tracks, 3 repeats: **2,457 judgements, 36,855 item
scores.** Fully documented in
[`final_evaluations/results_v2/README.md`](final_evaluations/results_v2/README.md),
which covers the panel and why each model was chosen, the scoring protocol,
item→construct mapping, reverse coding, every exclusion, the record schema, CSV
columns and the statistical methods.

The 2026 judge panel — one model per lab, each verified to accept image input
and return parseable structured scores:

| Judge | Lab |
|---|---|
| `openai/gpt-5.6-sol` | OpenAI — generator's own lab, analysed as a separate stratum |
| `anthropic/claude-opus-5` | Anthropic |
| `google/gemini-3.6-flash` | Google |
| `mistralai/mistral-medium-3-5` | Mistral AI |
| `x-ai/grok-4.5` | xAI |
| `qwen/qwen3.8-max` | Alibaba |
| `moonshotai/kimi-k3` | Moonshot AI |

Selection criteria and rejected candidates, with reasons, are in
`final_evaluations/judge_panel.json`.

### `final_evaluations/results/` — archival

The 2025 single-run scores, five evaluator LLMs (GPT-5, Claude Sonnet 4.5,
Gemini 2.5 Pro, Mistral Medium 3.1, DeepSeek 3.2), one file of 15 scores each:

```
final_evaluations/results/{security|inclusivity}/case_{1|2|3}/case_{N}_{model}.txt
```

The artifacts those scores describe are in
`workspace/password_recovery_health/<case>/legacy_single_run_gpt4o/`, and their
screenshots in `screenshots/<case>/`. Despite the directory name, the recorded
token pricing shows these were generated with `openai/gpt-5`; the name comes
from a stale `.env` example corrected in commit `2c980c3`.

Generation metrics for those three artifacts:

| Case | Iterations | Input tokens | Output tokens | Cost (USD) |
|------|------------|--------------|---------------|------------|
| 1 | 4 | 87,179 | 94,459 | $1.05 |
| 2 | 2 | 35,793 | 41,730 | $0.46 |
| 3 | 3 | 84,923 | 84,503 | $0.95 |

### Rubrics

15 items each, five constructs of three, on a 1–5 Likert scale.

**Security — identical across both stories and both collections**, so security
is comparable throughout:

| Construct | Items |
|---|---|
| A01:2021 Broken Access Control | 1–3 |
| A02:2021 Cryptographic Failures | 4–6 |
| A03:2021 Injection / XSS | 7–9 |
| A05:2021 Security Misconfiguration | 10–12 |
| A07:2021 Identification and Authentication Failures | 13–15 |

Items 2 and 3 are reverse-worded — agreeing means the system is *less* secure —
and are inverted (`6 − x`) before aggregation in `results_v2/`. The rule is the
same in both stories by design.

**Inclusivity — the dimensions differ by story**, because the stories target
different conditions:

| Items | Story 1 (ADHD) | Story 2 (dyslexia) |
|---|---|---|
| 1–3 | Attention | Readability |
| 4–6 | Memory | Reading load |
| 7–9 | Comprehension | Transcription |
| 10–12 | Decision making | Orientation |
| 13–15 | Learning | Recovery |

> Inclusivity may be compared between the stories at the **overall score** level
> only. Construct-level comparison across stories is meaningless.

## Human Evaluation

### The 2026 package

`human_evaluation_package/` holds the six best-scoring artifacts — one per case
per user story — prepared for expert review. Two evaluations run against the
same six artifacts:

| Evaluation | What the expert gets | How |
|---|---|---|
| Security | the source code | `human_evaluation_package/source_code/` |
| Inclusivity | a live, clickable application | `human_evaluation_package/deploy_cloudflare/` |

All six source files are byte-identical to model output, with SHA-256 sums in
`source_code/MANIFEST.csv` verified against the generation manifests. A blinded
copy of the set (`artifact_A.ts` … `artifact_F.ts`, key held separately) is
provided for experts scoring more than one artifact, since the descriptive
filenames otherwise disclose the experimental condition.

The live applications run as **Cloudflare Containers**, not Pages: the artifacts
are Bun servers using `Bun.serve`, `Bun.password`, `node:fs` and `node:crypto`,
none of which exist on the Workers runtime. Each judge is routed to a private
container instance, because the artifacts hold state in process memory and
several key it globally — on a shared instance one judge's MFA enrolment is
visible to the next, and five failed sign-ins lock the demo account for
everyone. Two deployment accommodations are documented in
`human_evaluation_package/deploy_cloudflare/README.md` and must be disclosed
alongside any result: a self-signed certificate on the container loopback, and
rewriting of `Host`/`Origin`/`Referer` so that the three artifacts which pin
their origin to `localhost` will accept requests from a public hostname. No
`app.ts` is modified.

`best_run_screenshots/` holds the same six artifacts photographed step by step,
for readers who want to see them without deploying anything.

### The 2025 expert assessment

Human experts assessed the 2025 artifacts.

### Survey Instruments

`survey_questionnaires/` contains the PDF forms used for data collection:

| File | Pages | Purpose |
|------|-------|---------|
| `inclusivity_evaluation_survey.pdf` | 8 | Cognitive accessibility assessment instrument |
| `security_evaluation_survey.pdf` | 8 | OWASP-based security assessment instrument |

### Human Expert Results

| File | Evaluators | Background |
|------|------------|------------|
| `inclusivity_evaluation_results.xlsx` | 5 | Software engineers, researchers, HR professionals |
| `security_evaluation_results.xlsx` | 8 | Security engineers, malware researchers, developers |

**Inclusivity experts (n=5)**

| Role | Experience |
|------|------------|
| Software Engineer | 9 years |
| Human Resource Manager | 4 years |
| Lecturer | 5 years |
| Junior Researcher | 1 year |
| Project Researcher | 10 years |

**Security experts (n=8)**

| Role | Experience |
|------|------------|
| Web Developer | 1 year |
| Full Stack Developer | 3 years |
| Vulnerability Management Trainee | 2 years |
| Senior Cyber Security Engineer | 4 years |
| Security Researcher | 1 year |
| Malware Researcher | 4 years |
| Senior Malware Researcher | 5 years |
| Lecturer (Information Security) | 5 years |

Each results file contains raw per-evaluator scores per item, a case breakdown,
and average / median / variance / standard deviation.

**Candidates for a repeat human evaluation.** `report.py` ranks all 60 of the
2026 artifacts and names the best per case, so a human panel can be given a
defensible selection rather than a hand-picked one:
`final_evaluations/results_v2/cross_study/05_best_run_per_case.csv`.

## Software Dependencies

| Software | Version | Purpose |
|----------|---------|---------|
| Python | ≥ 3.13 | Pipeline and analysis |
| Bun | 1.3.14 | TypeScript execution for generated code (the prompts declare 1.3.0) |
| LangGraph | ≥ 0.6.7 | Multi-agent orchestration |
| LangChain-OpenAI | ≥ 0.3.33 | OpenAI / OpenRouter integration |
| LangChain-Anthropic | ≥ 0.3.20 | Anthropic integration |
| Playwright | ≥ 1.62 | Chromium, for client-script checks and screenshot capture |
| pandas, scipy, statsmodels, pingouin | — | Statistics |
| openpyxl | ≥ 3.1.5 | Workbook export |

See `pyproject.toml` for the complete list.

## Citation

Archived on Zenodo at each tagged release. Cite the **concept DOI**, which
always resolves to the newest version. See [PUBLISHING.md](PUBLISHING.md) for
how the archive is produced and how to update the DOI once minted.

Machine-readable metadata: [CITATION.cff](CITATION.cff) and
[.zenodo.json](.zenodo.json).

For the paper:

```bibtex
TBA
```

For the dataset:

```bibtex
TBA
```

## License

MIT — see [LICENSE](LICENSE). This covers the pipeline, the analysis scripts and
the documentation. The generated artifacts under `generations/` and
`workspace/` are model output, reproduced unmodified as the object of study.

## Contact

TBA

## Acknowledgments

TBA
