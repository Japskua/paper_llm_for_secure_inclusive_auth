import pathlib
from datetime import datetime
from httpx import HTTPError, ReadTimeout

# args holder to avoid circular imports and keep vprint/safe_invoke simple
ARGS = None


def set_args(args):
    """Set global args for this module (to support vprint/safe_invoke)."""
    global ARGS
    ARGS = args


def vprint(*msg):
    """Verbose print with timestamp if args.verbose is True."""
    if ARGS and getattr(ARGS, "verbose", False):
        print(f"[{datetime.now().strftime('%H:%M:%S')}]", *msg, flush=True)


def safe_invoke(llm, messages, who: str, iter_no: int):
    """Invoke an LLM with basic crash handling and on-disk markers."""
    vprint(f"[iter {iter_no}] {who}: invoking")
    try:
        resp = llm.invoke(messages)
        return resp
    except (ReadTimeout, HTTPError) as e:
        print(f"[FATAL] {who} request failed: {e}")
        if ARGS and getattr(ARGS, "output", None):
            pathlib.Path(ARGS.output, f"CRASH_{who}_iter{iter_no}.txt").write_text(
                str(e), encoding="utf-8"
            )
        raise
    except Exception as e:
        print(f"[FATAL] {who} unexpected error: {e}")
        if ARGS and getattr(ARGS, "output", None):
            pathlib.Path(ARGS.output, f"CRASH_{who}_iter{iter_no}.txt").write_text(
                str(e), encoding="utf-8"
            )
        raise


def normalize_content(content) -> str:
    """Normalize LangChain response content to a plain string."""
    if isinstance(content, list):
        return "".join(
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        )
    return str(content)
