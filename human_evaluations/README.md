# Human Evaluations: Expert Assessment Results

This directory contains aggregated evaluation results from human experts who assessed the LLM-generated code artifacts for security and inclusivity.

## Overview

Human evaluation was conducted via online surveys using [Webropol](https://webropol.com/). Experts received both the LLM-generated source code and UI screenshots for each experimental case.

## Files

| File | Evaluators | Items | Cases | Description |
|------|------------|-------|-------|-------------|
| `inclusivity_evaluation_results.xlsx` | 5 | 15 | 3 | Cognitive accessibility assessment |
| `security_evaluation_results.xlsx` | 8 | 15 | 3 | OWASP-based security assessment |

## Inclusivity Evaluation

### Evaluators (n=5)

| ID | Role | Experience |
|----|------|------------|
| P-1 | Software Engineer | 9 years |
| P-2 | Human Resource Manager | 4 years |
| P-3 | Lecturer | 5 years |
| P-4 | Junior Researcher | 1 year |
| P-5 | Project Researcher | 10 years |

**Mean experience**: 5.8 years (SD: 3.7)

### Evaluation Dimensions

The 15-item rubric assesses five cognitive dimensions (3 items each):

| Dimension | Items | Focus Area |
|-----------|-------|------------|
| Attention | 1-3 | UI cleanliness, element prominence, quick navigation |
| Memory | 4-6 | Minimal recall requirements, autofill options, recognition |
| Comprehension | 7-9 | Text clarity, error messages, examples |
| Decision Making | 10-12 | Clear choices, limited options, action feedback |
| Learning | 13-15 | Help tips, error recovery, consistency |

### Evaluation Input

- UI screenshots from `screenshots/` directory
- Inclusivity evaluation rubric

## Security Evaluation

### Evaluators (n=8)

| ID | Role | Experience |
|----|------|------------|
| P-6 | Web Developer | 1 year |
| P-7 | Full Stack Developer | 3 years |
| P-8 | Vulnerability Management Trainee | 2 years |
| P-9 | Senior Cyber Security Engineer | 4 years |
| P-10 | Security Researcher | 1 year |
| P-11 | Malware Researcher | 4 years |
| P-12 | Senior Malware Researcher | 5 years |
| P-13 | Lecturer (Information Security) | 5 years |

**Mean experience**: 3.1 years (SD: 1.6)

### Evaluation Dimensions

The 15-item rubric assesses five OWASP Top 10 (2021) categories (3 items each):

| OWASP Category | Items | Focus Area |
|----------------|-------|------------|
| A01:2021 Broken Access Control | 1-3 | Reset code validation, session handling |
| A02:2021 Cryptographic Failures | 4-6 | HTTPS/TLS, encryption, data protection |
| A03:2021 Injection/XSS | 7-9 | Input sanitization, safe redirects, template safety |
| A05:2021 Security Misconfiguration | 10-12 | Error handling, credential storage, defaults |
| A07:2021 Authentication Failures | 13-15 | Rate limiting, enumeration, token complexity |

### Evaluation Input

- Full source code (`app.ts`) from `workspace/` directory
- Security evaluation rubric

## Scoring Scale

All items use a 5-point Likert scale:

| Score | Security Interpretation | Inclusivity Interpretation |
|-------|------------------------|---------------------------|
| 1 | Critically Insecure | Strongly Disagree |
| 2 | Insecure | Disagree |
| 3 | Neutral | Neutral |
| 4 | Secure | Agree |
| 5 | Most Secure | Strongly Agree |

**Maximum possible score**: 75 (15 items × 5 points)

## File Structure

Each Excel file contains:

- **Raw scores**: Individual evaluator ratings for each item across all 3 cases
- **Aggregated statistics**: Average, Median, Variance, Standard Deviation
- **Per-case breakdown**: Separate columns for Case 1, Case 2, and Case 3

## Related Resources

- **Survey instruments**: See `../survey_questionnaires/` for the PDF questionnaires used
- **LLM evaluations**: See `../final_evaluations/results/` for comparison with LLM assessments
- **Evaluation rubrics**: See `../final_evaluations/evaluation_rubrics/` for detailed criteria

## Ethics

- All participants provided informed consent
- No personally identifiable information (PII) was collected
- Participation was voluntary and anonymous
