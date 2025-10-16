from dotenv import load_dotenv

from app.cli import parse_args, validate_args
from app.pipeline.multi import run_multi
from app.pipeline.single import run_single


def main():
    # Load .env
    load_dotenv()

    # Parse and validate CLI
    args = parse_args()
    validate_args(args)

    # Dispatch by mode
    if args.mode == "multi":
        run_multi(args)
    else:
        run_single(args)


if __name__ == "__main__":
    main()
