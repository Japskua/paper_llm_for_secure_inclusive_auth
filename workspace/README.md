# Workspace: Generated Code Artifacts

This directory contains the output artifacts from the multi-agent code generation pipeline for each experimental case.

## Directory Structure

```
workspace/
└── password_recovery_health/
    ├── case_1_multi_no_condition_no_inclusion/   # Case 1: No inclusivity
    ├── case_2_multi_condition_no_inclusion/      # Case 2: ADHD mentioned
    └── case_3_multi_condition_with_inclusion/    # Case 3: Detailed inclusivity
```

## File Descriptions

Each case directory contains the following files:

### Code Artifacts

| File | Description |
|------|-------------|
| `app.ts` | **Final generated code** - Complete TypeScript application with Bun server and client UI |
| `code_iter{N}.tsx` | Per-iteration code snapshots showing the iterative refinement process |

### Evaluation Reports

| File | Description |
|------|-------------|
| `evaluator_report.md` | Latest functional completeness evaluation report |
| `evaluator_report_iter{N}.md` | Per-iteration evaluation reports containing PASS/FAIL decisions |
| `tasker_report.md` | Latest task decomposition from the Tasker agent |
| `tasker_report_iter{N}.md` | Per-iteration task lists |

### Metadata and Logs

| File | Description |
|------|-------------|
| `log.jsonl` | Iteration metadata in JSON Lines format |
| `state.jsonl` | Serialized pipeline state after each iteration |
| `tokens_summary.json` | Cumulative token usage and API cost breakdown |
| `PASS_MARKER` | Empty file indicating successful completion |

## Log File Formats

### log.jsonl

Each line contains a JSON object with:

```json
{
  "iteration": 1,
  "duration_seconds": 45.2,
  "tasker_tokens": {"input": 1500, "output": 800},
  "coder_tokens": {"input": 3000, "output": 5000},
  "evaluator_tokens": {"input": 4000, "output": 2000},
  "task_count": 5,
  "decision": "FAIL"
}
```

### tokens_summary.json

Cumulative summary with cost breakdown:

```json
{
  "total": {
    "input_tokens": 87179,
    "output_tokens": 94459,
    "total_tokens": 181638
  },
  "by_role": {
    "tasker": {"input": 11369, "output": 9409},
    "coder": {"input": 34253, "output": 53901},
    "evaluator": {"input": 41557, "output": 31149}
  },
  "cost_usd": 1.05,
  "iterations": 4
}
```

## Running the Generated Applications

### Prerequisites

- [Bun](https://bun.sh/) runtime (v1.3.0+)
- TLS certificates for localhost

### Setup TLS Certificates

```bash
# Install mkcert
brew install mkcert  # macOS
# or: apt install mkcert  # Debian/Ubuntu

# Generate certificates
mkcert -install
mkdir -p certs
mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1
```

### Run Application

```bash
cd workspace/password_recovery_health/case_3_multi_condition_with_inclusion
bun app.ts
```

Access the application at: https://localhost:3000

## Code Generation Metrics Summary

| Case | Iterations | Total Tokens | Cost (USD) |
|------|------------|--------------|------------|
| Case 1 | 4 | 181,638 | $1.05 |
| Case 2 | 2 | 77,523 | $0.46 |
| Case 3 | 3 | 169,426 | $0.95 |
