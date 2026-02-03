# Final Evaluations: Rubrics and Results

This directory contains the evaluation instruments and LLM-based assessment results for the security and inclusivity evaluation of LLM-generated code.

## Directory Structure

```
final_evaluations/
├── evaluation_rubrics/              # Evaluation questionnaires
│   ├── security_eval_case_1.md
│   ├── security_eval_case_2.md
│   ├── security_eval_case_3.md
│   ├── inclusivity_eval_case_1.md
│   ├── inclusivity_eval_case_2.md
│   └── inclusivity_eval_case_3.md
└── results/                         # LLM evaluation scores
    ├── security/
    │   ├── case_1/
    │   ├── case_2/
    │   └── case_3/
    └── inclusivity/
        ├── case_1/
        ├── case_2/
        └── case_3/
```

## Evaluation Rubrics

### Security Evaluation (15 items)

Based on OWASP Top 10 (2021), assessing five attack categories:

| Category | Items | OWASP Code |
|----------|-------|------------|
| Broken Access Control | 1-3 | A01:2021 |
| Cryptographic Failures | 4-6 | A02:2021 |
| Injection/XSS | 7-9 | A03:2021 |
| Security Misconfiguration | 10-12 | A05:2021 |
| Authentication Failures | 13-15 | A07:2021 |

### Inclusivity Evaluation (15 items)

Based on five cognitive dimensions relevant to neurodivergent users:

| Dimension | Items | Focus Area |
|-----------|-------|------------|
| Attention | 1-3 | Clean UI, prominent elements, quick navigation |
| Memory | 4-6 | Minimal recall, autofill options, familiar items |
| Comprehension | 7-9 | Clear text, helpful errors, examples |
| Decision Making | 10-12 | Clear choices, limited options, feedback |
| Learning | 13-15 | Help tips, error recovery, consistency |

### Scoring Scale

All items use a 5-point Likert scale:

| Score | Security Interpretation | Inclusivity Interpretation |
|-------|------------------------|---------------------------|
| 1 | Critically Insecure | Strongly Disagree |
| 2 | Insecure | Disagree |
| 3 | Neutral | Neutral |
| 4 | Secure | Agree |
| 5 | Most Secure | Strongly Agree |

**Maximum possible score**: 75 (15 items x 5 points)

## LLM Evaluators

Five LLMs independently evaluated each code artifact:

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
3: [score]
...
15: [score]
```

Where `[score]` is an integer from 1 to 5.

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

## Key Observations

1. **Security scores** remained relatively consistent across cases (mean: 64.4 - 66.6)
2. **Inclusivity scores** showed clear improvement from Case 1 to Case 3 (55.4 to 65.6)
3. **Claude Sonnet 4.5** gave consistently higher security scores
4. **GPT-5** gave consistently higher inclusivity scores

## Usage Notes

- Security evaluations were performed using the full source code (`app.ts`)
- Inclusivity evaluations were performed using UI screenshots from `screenshots/`
- All evaluations were conducted in isolated sessions to prevent context contamination
- LLMs were instructed to respond only with numeric scores, no explanations
