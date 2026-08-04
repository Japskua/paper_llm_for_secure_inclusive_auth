# Experimental Dataset: Security and Inclusivity in LLM-Generated Code

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.XXXXXXX-blue)](https://doi.org/10.5281/zenodo.XXXXXXX)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

This repository contains the complete experimental dataset and replication materials for evaluating security and inclusivity in Large Language Model (LLM)-generated authentication code.

The data was generated and collected during September-October 2025.

## Related Publication

TBA

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Dataset Description](#dataset-description)
- [Quick Start](#quick-start)
- [Replicating the Experiment](#replicating-the-experiment)
- [Evaluation Data](#evaluation-data)
- [Human Evaluation Data](#human-evaluation-data)
- [Software Dependencies](#software-dependencies)
- [Citation](#citation)
- [License](#license)

## Overview

This dataset was generated through a controlled experiment examining the relationship between security and inclusivity in LLM-generated code. The experiment consisted of three cases with varying levels of inclusivity specification:

| Case | Inclusivity Level | Description |
|------|-------------------|-------------|
| **Case 1** | None | Security requirements only; no mention of cognitive conditions |
| **Case 2** | Moderate | Security requirements with cognitive condition (ADHD) mentioned |
| **Case 3** | Detailed | Security requirements plus detailed ADHD-specific inclusivity guidelines |

All three cases shared identical security requirements based on five OWASP Top 10 (2025) attack categories.

## Repository Structure

```
.
├── requirements/                        # INPUT: Action prompts (R₀, R₁, R₂)
│   └── password_recovery_health/
│       ├── password_recovery_health_no_inclusivity_no_condition.md  (Case 1)
│       ├── password_recovery_health_no_inclusivity.md               (Case 2)
│       └── password_recovery_health_with_inclusivity.md             (Case 3)
│
├── prompts/                             # PIPELINE: System prompts for agents
│   ├── prompt_tasker.txt                # LLM Tasker: requirement decomposition
│   ├── prompt_coder.txt                 # LLM Coder: code generation
│   ├── prompt_evaluator.txt             # Functional completeness validator
│   └── prompt_programmer_hitl.txt       # Single-agent HITL mode
│
├── workspace/                           # OUTPUT: Generated code artifacts
│   └── password_recovery_health/
│       ├── case_1_multi_no_condition_no_inclusion/   (C₀)
│       ├── case_2_multi_condition_no_inclusion/      (C₁)
│       └── case_3_multi_condition_with_inclusion/    (C₂)
│
├── final_evaluations/                   # EVALUATION: Rubrics and results
│   ├── evaluation_rubrics/              # 15-item questionnaires
│   │   ├── security_eval_case_{1,2,3}.md
│   │   └── inclusivity_eval_case_{1,2,3}.md
│   └── results/                         # LLM evaluation scores
│       ├── security/case_{1,2,3}/       # 5 LLMs × 3 cases = 15 files
│       └── inclusivity/case_{1,2,3}/    # 5 LLMs × 3 cases = 15 files
│
├── screenshots/                         # UI screenshots for evaluation
│   ├── case_1_multi_no_condition_no_inclusion/
│   ├── case_2_multi_condition_no_inclusion/
│   └── case_3_multi_condition_with_inclusion/
│
├── human_evaluations/                   # HUMAN EVAL: Expert assessment results
│   ├── inclusivity_evaluation_results.xlsx   # 5 experts, 15 items, 3 cases
│   └── security_evaluation_results.xlsx      # 8 experts, 15 items, 3 cases
│
├── survey_questionnaires/               # INSTRUMENTS: PDF survey forms
│   ├── inclusivity_evaluation_survey.pdf     # Cognitive accessibility rubric
│   └── security_evaluation_survey.pdf        # OWASP-based security rubric
│
├── software_descriptions/               # Detailed specification documents
│   └── password_recovery.md
│
└── app/                                 # Pipeline implementation (Python)
    ├── pipeline/multi.py                # Multi-agent orchestration
    ├── pipeline/single.py               # Human-in-the-loop mode
    └── utils/                           # Token counting, pricing utilities
```

## Dataset Description

### Input Data: Action Prompts

Three requirement specifications define the experimental conditions:

| File | Case | Lines | Inclusivity Content |
|------|------|-------|---------------------|
| `password_recovery_health_no_inclusivity_no_condition.md` | 1 | 49 | None |
| `password_recovery_health_no_inclusivity.md` | 2 | 49 | ADHD mentioned |
| `password_recovery_health_with_inclusivity.md` | 3 | 61 | Detailed ADHD guidelines |

### Output Data: Generated Code Artifacts

Each case directory in `workspace/password_recovery_health/` contains:

| File | Format | Description |
|------|--------|-------------|
| `app.ts` | TypeScript | Final LLM-generated password recovery application |
| `code_iter{N}.tsx` | TypeScript | Per-iteration code snapshots |
| `evaluator_report.md` | Markdown | Latest functional completeness report |
| `evaluator_report_iter{N}.md` | Markdown | Per-iteration evaluation reports |
| `tasker_report.md` | Markdown | Latest task decomposition |
| `tasker_report_iter{N}.md` | Markdown | Per-iteration task lists |
| `log.jsonl` | JSON Lines | Iteration metadata (duration, tokens) |
| `state.jsonl` | JSON Lines | Pipeline state snapshots |
| `tokens_summary.json` | JSON | Token usage and cost breakdown |
| `PASS_MARKER` | Empty | Indicates successful completion |

### Code Generation Metrics

| Case | Iterations | Input Tokens | Output Tokens | Total Tokens | Cost (USD) |
|------|------------|--------------|---------------|--------------|------------|
| 1 | 4 | 87,179 | 94,459 | 181,638 | $1.05 |
| 2 | 2 | 35,793 | 41,730 | 77,523 | $0.46 |
| 3 | 3 | 84,923 | 84,503 | 169,426 | $0.95 |

### Evaluation Data

The `final_evaluations/` directory contains:

- **Security rubrics**: 15-item questionnaire based on OWASP Top 10 (2025)
  - A01:2021 Broken Access Control (Items 1-3)
  - A02:2021 Cryptographic Failures (Items 4-6)
  - A03:2021 Injection/XSS (Items 7-9)
  - A05:2021 Security Misconfiguration (Items 10-12)
  - A07:2021 Authentication Failures (Items 13-15)

- **Inclusivity rubrics**: 15-item questionnaire based on cognitive dimensions
  - Attention (Items 1-3)
  - Memory (Items 4-6)
  - Comprehension (Items 7-9)
  - Decision Making (Items 10-12)
  - Learning (Items 13-15)

- **LLM evaluation results**: Scores from 5 evaluator LLMs
  - GPT-5 (OpenAI)
  - Claude Sonnet 4.5 (Anthropic)
  - Gemini 2.5 Pro (Google)
  - Mistral Medium 3.1 (Mistral AI)
  - DeepSeek 3.2 (DeepSeek)

## Quick Start

### Accessing the Dataset

```bash
# Clone the repository
git clone https://github.com/[organization]/paper_llm_for_secure_inclusive_auth.git
cd paper_llm_for_secure_inclusive_auth

# Review generated code artifacts
ls workspace/password_recovery_health/

# Review evaluation rubrics
ls final_evaluations/evaluation_rubrics/

# Review LLM evaluation results
ls final_evaluations/results/
```

### Running Generated Applications

The generated TypeScript applications require [Bun](https://bun.sh/) runtime:

```bash
# Install Bun (if not installed)
curl -fsSL https://bun.sh/install | bash

# Generate TLS certificates (required for HTTPS)
brew install mkcert  # macOS
mkcert -install
mkdir -p certs && mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1

# Run Case 3 application
cd workspace/password_recovery_health/case_3_multi_condition_with_inclusion
bun app.ts
# Access at https://localhost:3000
```

## Replicating the Experiment

### Prerequisites

- Python >= 3.13
- [uv](https://github.com/astral-sh/uv) (recommended) or pip
- LLM API access (OpenAI, Anthropic, or OpenRouter)

### Installation

```bash
# Using uv (recommended)
pip install uv
uv venv
source .venv/bin/activate
uv sync

# Using pip
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Create a `.env` file from the template:

```bash
cp .env.example .env
```

Configure your LLM provider:

```env
# OpenRouter (recommended for reproducibility)
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=openai/gpt-5

# Token pricing (USD per 1M tokens)
PRICE_INPUT_PER_1M=1.25
PRICE_OUTPUT_PER_1M=10.00
```

### Running Code Generation (repeated-runs design)

The experiment generates **10 independent runs per case** (30 runs total) so that
between-case differences can be tested against between-run variance. Use the batch
runner:

```bash
uv run python run_batch.py \
  --software password_recovery_health \
  --runs 10 \
  --concurrency 6 \
  --max-iters 12 \
  --model openai/gpt-5.6-terra \
  --reasoning-effort medium \
  --smoke-test
```

Useful flags: `--dry-run` lists the planned runs, `--cases` restricts to a subset,
`--run-start` extends an existing batch, `--force` re-runs completed runs. Runs
already completed are skipped, so an interrupted batch can simply be re-invoked.

Each run executes in its own subprocess (isolating token counters and containing
crashes) and writes to `generations/<software>/<case>/run_NN/`. The batch writes
`generations/<software>/batch_manifest.json`, which records per run: model, exact
dated model snapshot, resolved upstream provider, sampling configuration, iteration
count, convergence, token usage including reasoning tokens, cost, `app.ts` SHA-256,
and smoke-test result. That manifest is the input to the evaluation stage.

The earlier single-run GPT-4o dataset remains under
`workspace/<software>/<case>/legacy_single_run_gpt4o/` (moved there by
`--archive-legacy`), keeping the two generations of results clearly separated.

#### Pinning the upstream provider

OpenRouter may serve one model id from several upstream backends. In a validation
batch, 11 of 12 calls in one run went to OpenAI and 1 to Azure. Because different
backends can differ in serving configuration, pin routing before a real batch:

```env
OPENROUTER_PROVIDER_ORDER=openai
```

This sets `allow_fallbacks: false`; transient failures are absorbed by the retry
logic in `app/utils/io.py` rather than by silently switching backend. The provider
actually used is recorded per run either way.

#### Sampling configuration

Runs are **independent draws**: no seed is ever sent, since a fixed seed would
suppress the between-run variance the design exists to measure.

Frontier reasoning models — the entire GPT-5.x family, Claude Sonnet 5 — do **not**
expose `temperature`; they sample at a fixed internal temperature. `provider.py`
queries each model's `supported_parameters` and sends `temperature` only when the
model accepts it, recording the effective setting per run. With
`openai/gpt-5.6-terra` the reported configuration is therefore
`temperature: null, temperature_supported: false`, and repeated runs vary through
the model's own sampling rather than a client-set parameter.

`reasoning_effort` **is** exposed, and materially affects both output quality and
token cost, so it is treated as a recorded experimental parameter (default
`medium`). If an explicitly set temperature is required, use a frontier model that
exposes one — `x-ai/grok-4.5`, `google/gemini-3.6-flash` and
`qwen/qwen3.8-max` all do — and pass `--temperature`.

#### Convergence

A run that reaches `--max-iters` without a PASS verdict writes a `NO_CONVERGENCE`
marker and is recorded with `converged: false`. Such runs are reported rather than
discarded: convergence rate is itself a per-case outcome.

#### Single run

To reproduce one artifact in isolation:

```bash
# Case 1: No inclusivity specification
uv run python run.py --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_no_inclusivity_no_condition.md \
  --output workspace/password_recovery_health/case_1_multi_no_condition_no_inclusion \
  --max-iters 12 --verbose

# Case 2: Moderate inclusivity specification
uv run python run.py --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_no_inclusivity.md \
  --output workspace/password_recovery_health/case_2_multi_condition_no_inclusion \
  --max-iters 12 --verbose

# Case 3: Detailed inclusivity specification
uv run python run.py --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_with_inclusivity.md \
  --output workspace/password_recovery_health/case_3_multi_condition_with_inclusion \
  --max-iters 12 --verbose
```

### Pipeline Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| LLM Provider | OpenRouter | API aggregation service |
| Code Generation Model | `openai/gpt-5.6-terra` | Same model for Tasker, Coder and Evaluator, consistent across all cases |
| Temperature | not client-exposed | Model samples at a fixed internal temperature; see *Sampling configuration* |
| Reasoning effort | `medium` | Recorded experimental parameter |
| Seed | none | Deliberately unset, to preserve between-run variance |
| Runs per case | 10 | Independent draws |
| Maximum Iterations | 12 | Upper bound for convergence |

### Changes to the Pipeline

The generation loop was hardened for unattended batch execution. Two changes alter
behaviour relative to the pipeline that produced the earlier single-run artifacts,
and are noted here for transparency:

1. **`NEW_TASKS` parsing.** The original parser accepted only `-`, `1.`, `2.` and
   `3.` line prefixes and stopped at the first blank line, so tasks numbered 4 and
   above were silently dropped and hierarchical task lists were flattened into a
   mixture of headings and sub-details. The parser in `app/utils/parsing.py` reads
   every outermost item and folds nested detail into its parent task.
2. **`DECISION` parsing.** The original required a line beginning literally with
   `DECISION` and fell back to `FAIL` otherwise, so a model writing
   `**DECISION:** PASS` would be forced to run to `--max-iters`. Markdown emphasis
   and heading markers are now tolerated.

Supporting changes without behavioural effect on a successful run: request timeout
raised from 60s to 900s (reasoning models routinely exceed 60s), transient API
failures retried with exponential backoff, Tasker JSON tolerant of code fences with
one corrective retry, reasoning tokens counted, cost taken from OpenRouter usage
accounting, and per-run artifacts always overwritten rather than skipped when
present.

### Verifying Generated Artifacts

`PASS_MARKER` records only that the Evaluator LLM judged the code complete; it does
not execute anything. With `--smoke-test`, each artifact is booted under Bun and
probed for a response, and the result is written to `run_NN/smoke.json` and
aggregated in the manifest. Ports are detected from the server's own startup log,
since generated apps variously hardcode a port or read `process.env.PORT`.

## Evaluation Data

### LLM Evaluator Results Format

Each result file in `final_evaluations/results/` contains 15 scores:

```
1: [score]
2: [score]
...
15: [score]
```

Where `[score]` is an integer from 1 (lowest) to 5 (highest).

### File Naming Convention

```
final_evaluations/results/{security|inclusivity}/case_{1|2|3}/case_{N}_{model-name}.txt
```

Example: `final_evaluations/results/security/case_1/case_1_gpt-5.txt`

## Human Evaluation Data

In addition to LLM-based evaluation, human experts assessed the generated code artifacts.

### Survey Instruments

The `survey_questionnaires/` directory contains the PDF survey forms used for data collection:

| File | Pages | Purpose |
|------|-------|---------|
| `inclusivity_evaluation_survey.pdf` | 8 | Cognitive accessibility assessment instrument |
| `security_evaluation_survey.pdf` | 8 | OWASP-based security assessment instrument |

### Human Expert Results

The `human_evaluations/` directory contains aggregated results from expert assessments:

| File | Evaluators | Background |
|------|------------|------------|
| `inclusivity_evaluation_results.xlsx` | 5 | Software engineers, researchers, HR professionals |
| `security_evaluation_results.xlsx` | 8 | Security engineers, malware researchers, developers |

### Evaluator Demographics

**Inclusivity Experts (n=5)**
| Role | Experience |
|------|------------|
| Software Engineer | 9 years |
| Human Resource Manager | 4 years |
| Lecturer | 5 years |
| Junior Researcher | 1 year |
| Project Researcher | 10 years |

**Security Experts (n=8)**
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

### Excel File Structure

Each results file contains:
- **Raw scores**: Individual evaluator ratings per item (1-5 scale)
- **Case breakdown**: Separate columns for Case 1, 2, and 3
- **Statistics**: Average, Median, Variance, Standard Deviation

## Software Dependencies

| Software | Version | Purpose |
|----------|---------|---------|
| Python | >= 3.13 | Runtime environment |
| Bun | 1.3.0 | TypeScript execution for generated code |
| LangGraph | >= 0.6.7 | Multi-agent orchestration |
| LangChain-OpenAI | >= 0.3.33 | OpenAI/OpenRouter integration |
| LangChain-Anthropic | >= 0.3.20 | Anthropic integration |

See `pyproject.toml` for complete dependency list.

## Citation

If you use this dataset in your research, please cite:

```bibtex
TBA
```

For the dataset:

```bibtex
TBA
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions about this dataset, please contact:
- TBA

## Acknowledgments

TBA
