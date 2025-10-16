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

    return parser.parse_args()


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
