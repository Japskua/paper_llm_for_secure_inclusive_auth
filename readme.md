# Multi‑Agent HTML Builder with Evaluator Loop

## Quick start

Multi‑agent run (Tasker → Coder → Evaluator)
Using uv:

### Running the health scenarios

#### Scenario 1 - Multi-agents with no inclusivity requirements and no condition mentioned

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_no_inclusivity_no_condition.md \
  --output workspace/password_recovery_health/case_1_multi_no_condition_no_inclusion \
  --max-iters 12 \
  --verbose
```

#### Scenario 2 - Multi-agents with no inclusivity requirements

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_no_inclusivity.md \
  --output workspace/password_recovery_health/case_2_multi_condition_no_inclusion \
  --max-iters 12 \
  --verbose
```

#### Scenario 3 - Multi-agents with inclusivity requirements

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_health/password_recovery_health_with_inclusivity.md \
  --output workspace/password_recovery_health/case_3_multi_condition_with_inclusion \
  --max-iters 12 \
  --verbose
```

### Education case

#### Scenario 3 - Multi-agents with no inclusivity requirements and no condition mentioned

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_education/password_recovery_education_no_inclusivity_no_condition.md \
  --output workspace/password_recovery_education/case_1_multi_no_condition_no_inclusion \
  --max-iters 12 \
  --verbose
```

#### Scenario 2 - Multi-agents with no inclusivity requirements and condition mentioned

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_education/password_recovery_education_no_inclusivity.md \
  --output workspace/password_recovery_education/case_2_multi_condition_no_inclusion \
  --max-iters 12 \
  --verbose
```

#### Scenario 3 - Multi-agents with inclusivity requirements

```bash
uv run python run.py \
  --mode multi \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery_education/password_recovery_education_with_inclusivity.md \
  --output workspace/password_recovery_education/case_3_multi_condition_with_inclusion\
  --max-iters 12 \
  --verbose
```

This project runs a constrained, multi‑agent loop (Tasker → Coder → Evaluator) to iteratively build a single‑file web artifact (index.html) from a natural‑language Requirements document. It logs iterations, evaluator reports, token usage, and (optionally) estimated cost.

The code is intentionally simple and reproducible:

-   One artifact: index.html (client‑only, no servers or external calls)
-   Deterministic runs by default (temperature=0.0)
-   Robust logging, crash markers, and token accounting

## How it works

High‑level flow:
The run.py entrypoint loads .env, parses CLI, and dispatches to app/pipeline/multi.py (multi-agent) or app/pipeline/single.py (single-agent).

1. Tasker
    - Reads Requirements and last Evaluator feedback.
    - Produces strict JSON: { "task_list": [...] }.
    - Note: Evaluator is authoritative for termination; Tasker does not toggle done. If Tasker returns an empty task_list, previous tasks are retained.
2. Coder
    - Receives the current tasks and the current index.html.
    - Returns the full, updated index.html wrapped between <FILE> ... </FILE>.
    - Must implement only client‑side code and follow acceptance criteria exactly.
3. Evaluator
    - Compares index.html against the Requirements (and acceptance criteria).
    - Outputs a Markdown report with: SUMMARY, FUNCTIONAL_CHECK, FAILING_ITEMS, NEW_TASKS, DECISION.
    - If DECISION=PASS → loop terminates; else NEW_TASKS are fed back to the next Tasker step.

This loop executes up to --max-iters iterations or until the Evaluator returns PASS. Each role is an LLM instance (potentially the same or different models). The graph and state machine are implemented with LangGraph.

### Iteration semantics and termination behavior

-   One outer iteration runs exactly one Tasker → Coder → Evaluator triplet. The graph ends after the Evaluator node; the outer loop advances the iteration counter.
-   Evaluator is authoritative on completion:
    -   DECISION=PASS → state.done=True and the loop terminates. Tasks are cleared.
    -   DECISION=FAIL → state.done=False and NEW_TASKS are parsed and fed to the next iteration.
-   Defensive PASS hard-stop: After each triplet, the outer loop also inspects the latest evaluator_report content; if it contains DECISION: PASS, it forces done=True and writes a PASS_MARKER file in the output directory. This belt-and-suspenders guard guarantees termination even if state becomes desynchronized.
-   Tasker behavior: Tasker only updates task_list when it returns a non-empty list; if it returns an empty list, the previous tasks are retained. Tasker does not toggle done.
-   Evaluator NEW_TASKS filtering: sentinel entries like "None", "None.", "N/A", or "No tasks" are dropped to avoid phantom tasks. If nothing remains, the next iteration receives an empty task list.
-   Logging clarity: Each node invocation increments an inner step counter and prefixes logs with “[iter N | step K]”. Tasker report titles include the same prefix.

Artifacts per iteration:

-   workspace/<your_case>/index.html (latest)
-   workspace/<your_case>/index_iterN.html (versioned)
-   workspace/<your_case>/evaluator_report.md (latest)
-   workspace/<your_case>/evaluator_report_iterN.md (versioned)
-   workspace/<your_case>/tasker_report.md (latest)
-   workspace/<your_case>/tasker_report_iterN.md (versioned, first-write-only per iteration)
-   workspace/<your_case>/log.jsonl (timing + token deltas per iter)
-   workspace/<your_case>/state.jsonl (serialized state snapshots)
-   workspace/<your_case>/tokens_summary.json (final token usage and optional cost)
-   workspace/<your_case>/PASS_MARKER (created when the evaluator returns PASS; aids auditability and confirms hard-stop)

## Repository layout (key files)

-   run.py — Thin entry point: loads .env, parses CLI, dispatches to pipelines
-   app/
    -   cli.py — CLI parsing and validation (mode-aware)
    -   constants.py — Shared constants (INIT_CODE HTML skeleton)
    -   utils/
        -   io.py — vprint, safe_invoke, normalize_content (with crash markers)
        -   tokens.py — TOK counters, add_usage, extract_usage
        -   pricing.py — load_pricing, compute_cost_usd_per_1M
        -   summary.py — finalize_summary (writes tokens_summary.json and prints usage/cost)
    -   pipeline/
        -   multi.py — Tasker → Coder → Evaluator loop (LangGraph), run_multi()
        -   single.py — Single-agent programmer HITL loop, run_single()
-   provider.py — Creates LLM clients for roles based on env (OpenAI, OpenRouter, Anthropic).
-   prompts/
    -   prompt_tasker.txt — Enforces JSON output with task_list only (no done).
    -   prompt_coder.txt — Forces full index.html output within <FILE> tags.
    -   prompt_evaluator.txt — Yields a structured Markdown report incl. DECISION.
    -   prompt_programmer_hitl.txt — System prompt for single-agent HITL.
    -   prompt_inclusivity_eval.txt — Provided but not wired by default (see Inclusivity note below).
-   requirements/
    -   password_recovery/\*.md — Example requirement specs (with/without inclusivity).
    -   two_factor_auth/ — Placeholder for additional scenarios.
-   evalution_rubrics/
    -   inclusivity_rubric.md — Example rubric you may want to embed in your Requirements.
-   workspace/ — Output cases, logs, and artifacts.

## Prerequisites

-   Python ≥ 3.13 (see pyproject.toml)
-   An LLM API provider: OpenAI, OpenRouter, or Anthropic
-   API keys for your chosen provider
-   Recommended: uv for dependency management (fast, lockfile‑aware)

## Installation

Option A: Using uv (recommended)

-   Install uv (one of):
    -   macOS (Homebrew): brew install uv
    -   pipx: pipx install uv
-   Create and activate a virtualenv, then sync deps:
    -   uv venv
    -   source .venv/bin/activate
    -   uv sync

Option B: Using pip (manual)

-   Create and activate a virtualenv (Python 3.13+), then install deps:
    -   python -m venv .venv
    -   source .venv/bin/activate
    -   pip install -U pip
    -   pip install anthropic langchain-anthropic langchain-openai langgraph openai python-dotenv tiktoken

## Configuration

1. Copy .env.example to .env and fill in your provider keys.

Pick exactly one provider:

-   OpenAI

    -   LLM_PROVIDER=openai
    -   OPENAI_API_KEY=sk-...
    -   OPENAI_MODEL=gpt-4o
    -   Optional per-role overrides:
        -   OPENAI_TASKER_MODEL, OPENAI_CODER_MODEL, OPENAI_EVALUATOR_MODEL

-   OpenRouter

    -   LLM_PROVIDER=openrouter
    -   OPENROUTER_API_KEY=sk-or-...
    -   OPENROUTER_MODEL=openai/gpt-4o (or any supported, e.g. anthropic/claude-3.5-sonnet, meta-llama/llama-3.1-405b-instruct)
    -   Optional:
        -   OPENROUTER_TASKER_MODEL, OPENROUTER_CODER_MODEL, OPENROUTER_EVALUATOR_MODEL
        -   OPENROUTER_REFERER, OPENROUTER_SITE_NAME (helps with OpenRouter policy/attribution)

-   Anthropic
    -   LLM_PROVIDER=anthropic
    -   ANTHROPIC_API_KEY=sk-ant-...
    -   ANTHROPIC_MODEL=claude-3-5-sonnet-latest
    -   Optional per-role overrides:
        -   ANTHROPIC_TASKER_MODEL, ANTHROPIC_CODER_MODEL, ANTHROPIC_EVALUATOR_MODEL

Optional pricing (USD per 1M tokens) for cost estimation:

-   Global defaults:
    -   PRICE_INPUT_PER_1M, PRICE_CACHED_INPUT_PER_1M, PRICE_OUTPUT_PER_1M
-   Per-role overrides:
    -   PRICE_TASKER_INPUT_PER_1M, PRICE_TASKER_CACHED_INPUT_PER_1M, PRICE_TASKER_OUTPUT_PER_1M
    -   PRICE_CODER_INPUT_PER_1M, PRICE_CODER_CACHED_INPUT_PER_1M, PRICE_CODER_OUTPUT_PER_1M
    -   PRICE_EVALUATOR_INPUT_PER_1M, PRICE_EVALUATOR_CACHED_INPUT_PER_1M, PRICE_EVALUATOR_OUTPUT_PER_1M

If any needed rate is missing, cost computation is skipped (token usage is always recorded).

## Running

General CLI:

-   python run.py --tasker prompts/prompt_tasker.txt --coder prompts/prompt_coder.txt --eval prompts/prompt_evaluator.txt --requirements <requirements.md> [--criteria <rubric.md>] --output <output_dir> [--max-iters N] [-v]

Flags:

-   --tasker, --coder, --eval: system prompts for each role
-   --requirements: scenario specification (functional + acceptance criteria)
-   --criteria: optional inclusivity rubric (note: not injected by default; see Inclusivity note below)
-   --output: directory for artifacts, logs, and reports
-   --max-iters: maximum loop cycles (default 8)
-   -v/--verbose: prints prompts, token usage per step, and timings

Example A: Password recovery (no inclusivity)

-   python run.py --tasker prompts/prompt_tasker.txt --coder prompts/prompt_coder.txt --eval prompts/prompt_evaluator.txt --requirements requirements/password_recovery/password_recovery_no_inclusivity.md --output workspace/password_recovery/case_1 -v

Example B: Password recovery (with inclusivity considerations embedded in requirements)

-   python run.py --tasker prompts/prompt_tasker.txt --coder prompts/prompt_coder.txt --eval prompts/prompt_evaluator.txt --requirements requirements/password_recovery/password_recovery_with_inclusivity.md --output workspace/password_recovery/case_2 -v

Two‑factor auth (if you add a requirements.md there):

-   python run.py --tasker prompts/prompt_tasker.txt --coder prompts/prompt_coder.txt --eval prompts/prompt_evaluator.txt --requirements requirements/two_factor_auth/<your_requirements>.md --output workspace/two_factor_auth/case_1 -v

## Outputs you can expect

In your chosen --output folder:

-   index.html — latest artifact (client‑only web app)
-   index_iterN.html — artifact snapshot per iteration
-   evaluator_report.md — latest evaluator Markdown
-   evaluator_report_iterN.md — evaluator report per iteration
-   tasker_report.md — latest Tasker Markdown
-   tasker_report_iterN.md — per‑iteration Tasker Markdown
-   log.jsonl — per‑iteration duration and token deltas
-   state.jsonl — serialized state after each iteration
-   tokens_summary.json — cumulative token usage and optional cost breakdown

If an API call fails, a CRASH\_<ROLE>\_iterN.txt file is written with the error. Use -v to inspect prompts and timings.

## Single‑agent programmer (HITL) mode

You can now run a true single‑agent workflow with a programmer agent and human‑in‑the‑loop chat. The agent immediately implements from the Requirements, writes index.html, and then you can iteratively chat with it via the CLI until you accept.

Basic usage:

```bash
uv run python run.py \
  --mode single \
  --programmer prompts/prompt_programmer_hitl.txt \
  --requirements requirements/password_recovery/password_recovery_no_inclusivity.md \
  --output workspace/password_recovery/case_single_1 \
  -v
```

Notes:

-   --programmer is optional; if omitted, the system falls back to --coder (if provided) or a built‑in programmer prompt.
-   The artifact layout and logging match multi‑agent mode: index.html, index_iterN.html, log.jsonl, state.jsonl, tokens_summary.json.
-   Token usage in single mode is accounted under the "coder" bucket to keep pricing simple.

Interactive CLI commands during single mode:

-   accept — finalize and write summary
-   status — show iteration, artifact size, and token totals
-   help — list commands
-   cancel — abort and write summary
-   Any other input is treated as instructions to the programmer. If code changes are needed, the agent returns the full index.html between <FILE>...</FILE> and a new versioned snapshot is saved.

## Inclusivity criteria (important note)

-   The CLI supports --criteria, and run.py loads it; however, by default it is not currently injected into the Evaluator prompt.
-   To enforce inclusivity, include the criteria or thresholds inside your Requirements document (e.g., password_recovery_with_inclusivity.md) so the Evaluator will judge against them as part of acceptance criteria.
-   The provided evalution_rubrics/inclusivity_rubric.md is a helpful reference if you want to embed key points directly into the Requirements.

## Tips and troubleshooting

-   Determinism: The system fixes temperature=0.0 in provider.make_three_llms for reproducibility.
-   Long outputs: The Coder must return the full index.html inside <FILE> ... </FILE>. If tags are missing, the entire output is treated as the file.
-   Verbose runs: Use -v to print a preview of model outputs and token usage per role and iteration.
-   Crash handling: If a network error occurs, a CRASH\_\* marker is written to the output folder with the exception text.
-   Token accounting: The script tries multiple metadata layouts to extract usage across providers. You'll always get raw usage in tokens_summary.json.
-   Cost estimation: Provide per‑1M token rates via .env. If missing, tokens_summary.json will explain that cost was skipped.

## Extending to new scenarios

-   Add a new Requirements file under requirements/<scenario>/<name>.md including acceptance criteria.
-   Optionally adjust system prompts under prompts/ for your scenario.
-   Run with a new --output path (e.g., workspace/<scenario>/case_X).
-   If you need assets beyond a single file, you'd need to generalize the Coder/Evaluator prompts and run.py to support multi‑file artifacts.

## Security and constraints

-   Coder prompt explicitly forbids servers or external calls. Keep everything client‑only within a single index.html.
-   Avoid leaking secrets: use .env for API keys; never commit .env.
-   Rate limits: If a provider throttles you, consider increasing timeouts or reducing --max-iters.

## License and citation

-   See repository license (if present).
-   Please cite this repository in academic or benchmarking contexts describing multi‑agent evaluation loops for inclusive authentication UX.
