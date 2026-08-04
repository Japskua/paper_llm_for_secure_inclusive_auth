import argparse
import pathlib
import os


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run multi-agent (Tasker→Coder→Evaluator) or single-agent programmer (HITL) loop for password recovery experiment."
    )

    parser.add_argument(
        "--mode",
        choices=["multi", "single"],
        default="multi",
        help="Run multi-agent pipeline (default) or single-agent programmer with HITL chat.",
    )
    # Multi-agent flags (conditionally required in multi mode)
    parser.add_argument("--tasker", required=False, help="Path to prompt_tasker.txt")
    parser.add_argument("--coder", required=False, help="Path to prompt_coder.txt")
    parser.add_argument(
        "--eval", dest="eval_", required=False, help="Path to prompt_eval.txt"
    )
    # Single-agent optional system prompt
    parser.add_argument(
        "--programmer",
        required=False,
        help="Path to prompt_programmer_hitl.txt (single mode).",
    )

    # Shared flags
    parser.add_argument(
        "--requirements", required=False, help="Path to requirements.md"
    )
    parser.add_argument("--output", required=False, help="Output folder for artifacts")
    parser.add_argument(
        "--criteria", required=False, help="Optional path to inclusivity rubric file"
    )
    parser.add_argument(
        "--max-iters",
        type=int,
        default=8,
        help="Maximum number of loop iterations in multi mode (default: 8)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose debug output (show prompts, responses, and timing).",
    )

    # Sampling / model configuration. These override .env so a batch can pin
    # the experimental parameters explicitly rather than relying on ambient env.
    parser.add_argument(
        "--model",
        required=False,
        help="Model id for all three agents (e.g. openai/gpt-5.6-terra). Overrides .env.",
    )
    parser.add_argument(
        "--reasoning-effort",
        required=False,
        choices=["minimal", "low", "medium", "high"],
        help="Reasoning effort for models that expose it. Recorded as an experimental parameter.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        required=False,
        help=(
            "Sampling temperature. Applied only if the model supports it; "
            "frontier reasoning models (GPT-5.x, Sonnet 5) do not expose it."
        ),
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="After the loop, boot the generated app.ts under Bun and verify it serves.",
    )
    parser.add_argument(
        "--certs",
        required=False,
        default="workspace/certs",
        help="Directory holding cert.pem/key.pem for the smoke test (default: workspace/certs).",
    )

    return parser.parse_args()


def apply_env_overrides(args: argparse.Namespace) -> None:
    """
    Push CLI overrides into the environment before provider.py reads them.
    Keeps provider configuration in one place while letting a batch runner pin
    parameters per run.
    """
    if getattr(args, "model", None):
        provider = os.getenv("LLM_PROVIDER", "openai").strip().lower()
        key = {
            "openai": "OPENAI_MODEL",
            "openrouter": "OPENROUTER_MODEL",
            "anthropic": "ANTHROPIC_MODEL",
        }.get(provider)
        if key:
            os.environ[key] = args.model
            # Clear per-role overrides so --model really applies to all agents.
            for role in ("TASKER", "CODER", "EVALUATOR"):
                os.environ.pop(f"{key.split('_')[0]}_{role}_MODEL", None)
    if getattr(args, "reasoning_effort", None):
        os.environ["OPENROUTER_REASONING_EFFORT"] = args.reasoning_effort
    if getattr(args, "temperature", None) is not None:
        os.environ["LLM_TEMPERATURE"] = str(args.temperature)


def validate_args(args: argparse.Namespace) -> None:
    # Per-mode required args presence
    if args.mode == "multi":
        missing = [
            name
            for name, val in [
                ("--tasker", args.tasker),
                ("--coder", args.coder),
                ("--eval", args.eval_),
                ("--requirements", args.requirements),
                ("--output", args.output),
            ]
            if not val
        ]
        if missing:
            raise SystemExit(
                f"Missing required arguments for multi mode: {' '.join(missing)}"
            )
    else:
        missing = [
            name
            for name, val in [
                ("--requirements", args.requirements),
                ("--output", args.output),
            ]
            if not val
        ]
        if missing:
            raise SystemExit(
                f"Missing required arguments for single mode: {' '.join(missing)}"
            )

    # File path validation
    if args.mode == "multi":
        for p in [args.tasker, args.coder, args.eval_, args.requirements]:
            if not pathlib.Path(p).is_file():
                raise FileNotFoundError(f"Required file not found: {p}")
    else:
        if not pathlib.Path(args.requirements).is_file():
            raise FileNotFoundError(f"Requirements not found: {args.requirements}")
        if args.programmer and not pathlib.Path(args.programmer).is_file():
            raise FileNotFoundError(f"Programmer prompt not found: {args.programmer}")

    if args.criteria and not pathlib.Path(args.criteria).is_file():
        raise FileNotFoundError(f"Inclusivity criteria file not found: {args.criteria}")

    # Ensure output folder exists
    os.makedirs(args.output, exist_ok=True)
