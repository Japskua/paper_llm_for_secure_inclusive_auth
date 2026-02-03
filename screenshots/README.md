# Screenshots: UI Documentation

This directory contains step-by-step screenshots of the password recovery user interface for each experimental case. These screenshots were used as input for the LLM-based inclusivity evaluation.

## Directory Structure

```
screenshots/
├── case_1_multi_no_condition_no_inclusion/   # Case 1: No inclusivity
├── case_2_multi_condition_no_inclusion/      # Case 2: ADHD mentioned
└── case_3_multi_condition_with_inclusion/    # Case 3: Detailed inclusivity
```

## Screenshot Contents

### Case 1: No Inclusivity Specification (4 screenshots)

| File | Step | Description |
|------|------|-------------|
| `step_1_login_page.png` | Login | Initial login page |
| `step_2_request_password_reset.png` | Request | Password reset request form |
| `step_3_verify_token.png` | Verify | Token verification screen |
| `step_4_set_new_password.png` | Reset | New password entry form |

### Case 2: Moderate Inclusivity (6 screenshots)

| File | Step | Description |
|------|------|-------------|
| `step_1_login_page.png` | Login | Initial login page |
| `step_2_request_password_reset.png` | Request | Password reset request form |
| `step_3_verify_token.png` | Verify | Token verification screen |
| `step_4_mfa_verification.png` | MFA | Multi-factor authentication |
| `step_5_set_new_password.png` | Reset | New password entry form |
| `step_6_completion.png` | Complete | Success confirmation |

### Case 3: Detailed Inclusivity (6 screenshots)

| File | Step | Description |
|------|------|-------------|
| `step_1_login_page.png` | Login | Initial login page |
| `step_2_request_password_reset.png` | Request | Password reset request form |
| `step_3_verify_token.png` | Verify | Token verification screen |
| `step_4_mfa_verification.png` | MFA | Multi-factor authentication |
| `step_5_set_new_password.png` | Reset | New password entry form |
| `step_6_completion.png` | Complete | Success confirmation |

## Usage in Evaluation

These screenshots served as input for the **inclusivity evaluation** by LLM evaluators:

1. Each LLM evaluator received all screenshots for a given case
2. Evaluators assessed the UI against the 15-item inclusivity rubric
3. Evaluation focused on cognitive accessibility for neurodivergent users (specifically ADHD)

### Evaluation Dimensions

The screenshots were evaluated across five cognitive dimensions:

- **Attention**: Clean UI, prominent elements, quick navigation
- **Memory**: Minimal recall requirements, autofill options
- **Comprehension**: Clear text, helpful error messages
- **Decision Making**: Clear choices, limited options at once
- **Learning**: Help tips, error recovery, consistency

## Visual Comparison

Comparing screenshots across cases reveals differences in:

1. **UI complexity**: Case 3 includes additional accessibility features
2. **Visual hierarchy**: Progressive improvement in element prominence
3. **Help text**: More contextual guidance in later cases
4. **Error handling**: Clearer error messages and recovery options

## File Format

- **Format**: PNG
- **Resolution**: Captured from browser at standard viewport
- **Size**: ~50-150 KB per image
