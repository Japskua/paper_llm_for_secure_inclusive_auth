# Survey Questionnaires: Evaluation Instruments

This directory contains the PDF survey instruments used for human expert evaluation of LLM-generated code artifacts.

## Files

| File | Pages | Size | Purpose |
|------|-------|------|---------|
| `inclusivity_evaluation_survey.pdf` | 8 | 803 KB | Cognitive accessibility assessment instrument |
| `security_evaluation_survey.pdf` | 8 | 803 KB | OWASP-based security assessment instrument |

## Survey Structure

Both surveys follow an identical structure:

1. **Introduction**: Research objectives and context
2. **User Story**: Helena's password recovery scenario (healthcare context)
3. **Evaluation Instructions**: 5-point Likert scale definitions
4. **Case Evaluations**: Separate sections for Case 1, 2, and 3
5. **15 Evaluation Items**: Grouped by dimension (5 dimensions × 3 items)

## Inclusivity Evaluation Survey

Assesses the user interface for cognitive accessibility, focusing on neurodivergent users (specifically ADHD).

### Evaluation Dimensions

| Dimension | Items | Example Criteria |
|-----------|-------|------------------|
| **Attention** | 1-3 | Clean UI without distractions, prominent important elements |
| **Memory** | 4-6 | Minimal recall requirements, autofill/password manager support |
| **Comprehension** | 7-9 | Short clear text, helpful error messages, examples provided |
| **Decision Making** | 10-12 | Clear choices, limited options at once, action feedback |
| **Learning** | 13-15 | Help tips available, easy error recovery, consistent design |

### Evaluator Input

- UI screenshots from each case (`screenshots/case_*/`)
- Written evaluation criteria in survey

## Security Evaluation Survey

Assesses the source code for security vulnerabilities based on OWASP Top 10 (2021).

### Evaluation Dimensions

| OWASP Category | Items | Example Criteria |
|----------------|-------|------------------|
| **A01:2021 Broken Access Control** | 1-3 | Reset code belongs to user, no cross-user access, session invalidation |
| **A02:2021 Cryptographic Failures** | 4-6 | HTTPS with latest TLS, proper encryption, protected email content |
| **A03:2021 Injection/XSS** | 7-9 | Input sanitization, safe redirects, template safety |
| **A05:2021 Security Misconfiguration** | 10-12 | No sensitive data in logs, secure credential storage, no defaults |
| **A07:2021 Authentication Failures** | 13-15 | Rate limiting, no username enumeration, complex random tokens |

### Evaluator Input

- Full source code (`workspace/*/app.ts`)
- Written evaluation criteria in survey

## Scoring Scale

Both surveys use a 5-point Likert scale:

| Score | Label | Description |
|-------|-------|-------------|
| 1 | Strongly Disagree / Critically Insecure | Does not meet criterion at all |
| 2 | Disagree / Insecure | Minimally meets criterion |
| 3 | Neutral | Partially meets criterion |
| 4 | Agree / Secure | Mostly meets criterion |
| 5 | Strongly Agree / Most Secure | Fully meets criterion |

## Cases Evaluated

| Case | Inclusivity Level | Description |
|------|-------------------|-------------|
| **Case 1** | None | Security requirements only; no cognitive condition mentioned |
| **Case 2** | Moderate | Security requirements with ADHD condition mentioned |
| **Case 3** | Detailed | Security requirements plus detailed ADHD-specific guidelines |

## Survey Platform

Surveys were administered via [Webropol](https://webropol.com/), an online survey platform.

## Related Resources

- **Evaluation results**: See `../human_evaluations/` for aggregated expert scores
- **LLM evaluation rubrics**: See `../final_evaluations/evaluation_rubrics/` for comparison
- **Generated code**: See `../workspace/password_recovery_health/` for evaluated artifacts
- **UI screenshots**: See `../screenshots/` for visual materials provided to inclusivity evaluators
