from dotenv import load_dotenv

from app.cli import apply_env_overrides, parse_args, validate_args
from app.pipeline.multi import run_multi
from app.pipeline.single import run_single


def main():
    # Load .env
    load_dotenv()

    # Parse and validate CLI
    args = parse_args()
    validate_args(args)

    # CLI model/sampling overrides must land in the environment before
    # provider.py constructs any LLM.
    apply_env_overrides(args)

    # Dispatch by mode
    if args.mode == "multi":
        run_multi(args)
    else:
        run_single(args)

    if getattr(args, "smoke_test", False):
        from app.utils.smoke import smoke_test

        result = smoke_test(args.output, certs_src=args.certs)
        status = "OK" if result["ok"] else "FAILED"
        print(
            f"Smoke test {status}: stage={result['stage']} "
            f"port={result['port']} status={result['status_code']}"
        )
        if not result["ok"]:
            print(f"  {result['error']}")

    if getattr(args, "flow_test", False):
        from app.utils.flow import flow_test
        from provider import make_llm

        result = flow_test(args.output, make_llm("evaluator"), certs_src=args.certs)
        status = "OK" if result.get("ok") else "FAILED"
        print(
            f"Flow test {status}: stage={result.get('stage')} "
            f"happy_path={result.get('happy_path_passed')}/{result.get('happy_path_total')} "
            f"negatives={result.get('negative_passed')}/{result.get('negative_total')}"
        )
        if not result.get("ok"):
            failed = [
                s["name"]
                for s in (result.get("steps") or [])
                if not s["ok"] and not s["expect_failure"]
            ]
            print(f"  {result.get('error') or 'failed steps: ' + ', '.join(failed)}")


if __name__ == "__main__":
    main()
