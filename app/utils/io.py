import pathlib
import random
import time
from datetime import datetime

from httpx import HTTPError, ReadTimeout

# args holder to avoid circular imports and keep vprint/safe_invoke simple
ARGS = None

# Retry policy for unattended batch runs. A single transient 429 three hours
# into a run used to kill it outright.
MAX_ATTEMPTS = 5
BASE_BACKOFF_S = 4.0
MAX_BACKOFF_S = 120.0

_TRANSIENT_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529}


def set_args(args):
    """Set global args for this module (to support vprint/safe_invoke)."""
    global ARGS
    ARGS = args


def vprint(*msg):
    """Verbose print with timestamp if args.verbose is True."""
    if ARGS and getattr(ARGS, "verbose", False):
        print(f"[{datetime.now().strftime('%H:%M:%S')}]", *msg, flush=True)


def _status_code(e: Exception):
    """Best-effort HTTP status extraction across httpx / openai / anthropic errors."""
    for attr in ("status_code", "http_status"):
        code = getattr(e, attr, None)
        if isinstance(code, int):
            return code
    resp = getattr(e, "response", None)
    code = getattr(resp, "status_code", None)
    return code if isinstance(code, int) else None


def _is_transient(e: Exception) -> bool:
    """Retry timeouts, connection errors and transient HTTP statuses; not 4xx client errors."""
    if isinstance(e, (ReadTimeout,)):
        return True
    code = _status_code(e)
    if code is not None:
        return code in _TRANSIENT_STATUS
    if isinstance(e, HTTPError):
        # Connection/transport errors carry no status code.
        return True
    # Rate-limit and overload errors that don't expose a status attribute.
    name = type(e).__name__.lower()
    return any(tag in name for tag in ("ratelimit", "timeout", "overloaded", "connection"))


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter, so parallel runs don't retry in lockstep."""
    delay = min(BASE_BACKOFF_S * (2 ** (attempt - 1)), MAX_BACKOFF_S)
    return delay * (0.5 + random.random())


def safe_invoke(llm, messages, who: str, iter_no: int):
    """
    Invoke an LLM, retrying transient failures with exponential backoff.
    Writes a CRASH_* marker and re-raises once retries are exhausted.
    """
    vprint(f"[iter {iter_no}] {who}: invoking")
    last_exc = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return llm.invoke(messages)
        except Exception as e:
            last_exc = e
            transient = _is_transient(e)
            code = _status_code(e)
            label = f"{type(e).__name__}" + (f" (HTTP {code})" if code else "")

            if not transient or attempt == MAX_ATTEMPTS:
                kind = "non-retryable" if not transient else "retries exhausted"
                print(f"[FATAL] {who} request failed ({kind}): {label}: {e}")
                if ARGS and getattr(ARGS, "output", None):
                    pathlib.Path(
                        ARGS.output, f"CRASH_{who}_iter{iter_no}.txt"
                    ).write_text(
                        f"attempts={attempt}\n{label}\n{e}\n", encoding="utf-8"
                    )
                raise

            delay = _backoff_delay(attempt)
            print(
                f"[RETRY] {who} attempt {attempt}/{MAX_ATTEMPTS} failed "
                f"({label}); retrying in {delay:.1f}s",
                flush=True,
            )
            time.sleep(delay)

    # Unreachable: the loop either returns or raises on its final attempt.
    raise RuntimeError(f"{who}: retry loop exited without result ({last_exc})")


def normalize_content(content) -> str:
    """Normalize LangChain response content to a plain string."""
    if isinstance(content, list):
        return "".join(
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        )
    return str(content)
