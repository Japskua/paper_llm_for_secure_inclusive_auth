# Experimental Dataset: Security and Inclusivity in LLM-Generated Code

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.XXXXXXX-blue)](https://doi.org/10.5281/zenodo.XXXXXXX)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

This repository contains the complete experimental dataset and replication materials for evaluating security and inclusivity in Large Language Model (LLM)-generated authentication code.

## Related Publication

> **Evaluating Security and Inclusivity in LLM-Generated Code: A Controlled Experiment**
> Naqvi, B., Parkkila, J., bin Shahid, W., & Afzal, H.
> *Information and Software Technology* (under review)

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Dataset Description](#dataset-description)
- [Quick Start](#quick-start)
- [Replicating the Experiment](#replicating-the-experiment)
- [Evaluation Data](#evaluation-data)
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

All three cases shared identical security requirements based on five OWASP Top 10 (2021) attack categories.

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

- **Security rubrics**: 15-item questionnaire based on OWASP Top 10 (2021)
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
OPENROUTER_MODEL=openai/gpt-4o

# Token pricing (USD per 1M tokens)
PRICE_INPUT_PER_1M=1.25
PRICE_OUTPUT_PER_1M=10.00
```

### Running Code Generation

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
| Code Generation Model | GPT-4o | Consistent across all cases |
| Temperature | 0.0 | Deterministic output |
| Maximum Iterations | 12 | Upper bound for convergence |

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
@article{naqvi2025security,
  title={Evaluating Security and Inclusivity in LLM-Generated Code: A Controlled Experiment},
  author={Naqvi, Bilal and Parkkila, Janne and bin Shahid, Waleed and Afzal, Hammad},
  journal={Information and Software Technology},
  year={2025},
  note={Under review}
}
```

For the dataset:

```bibtex
@dataset{naqvi2025dataset,
  title={Experimental Dataset for Evaluating Security and Inclusivity in LLM-Generated Code},
  author={Naqvi, Bilal and Parkkila, Janne and bin Shahid, Waleed and Afzal, Hammad},
  year={2025},
  publisher={GitHub/Zenodo},
  doi={10.5281/zenodo.XXXXXXX}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions about this dataset, please contact:
- Syed Bilal Naqvi - syed.naqvi@lut.fi

## Acknowledgments

This research was conducted at:
- Software Engineering, LENS, LUT University, Finland
- Information Security Group, Royal Holloway, University of London, UK
- School of Computing and Mathematical Sciences, University of Leicester, UK
