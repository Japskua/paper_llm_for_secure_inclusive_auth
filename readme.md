# Paper data and code

## Example run

```bash
uv run python run.py \
  --tasker prompts/prompt_tasker.txt \
  --coder prompts/prompt_coder.txt \
  --eval prompts/prompt_evaluator.txt \
  --requirements requirements/password_recovery/password_recovery_no_inclusivity.md \
  --output workspace/password_recovery/case_2 \
  --max-iters 8 \
  --verbose
```
