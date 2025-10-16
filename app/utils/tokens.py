from typing import Dict, Tuple, Any

# Global token counters (kept in-memory; also logged per-iter by callers)
TOK: Dict[str, Dict[str, int]] = {
    "tasker": {"input": 0, "output": 0, "cached_input": 0},
    "coder": {"input": 0, "output": 0, "cached_input": 0},
    "evaluator": {"input": 0, "output": 0, "cached_input": 0},
    "total": {"input": 0, "output": 0, "cached_input": 0},
}


def add_usage(agent: str, it: int, ot: int, cit: int) -> None:
    """
    Update cumulative token usage for a role and total.
    In single-agent mode we map unknown agent labels to 'coder' bucket for pricing simplicity.
    """
    agent_key = agent if agent in TOK else "coder"
    TOK[agent_key]["input"] += it
    TOK[agent_key]["output"] += ot
    TOK[agent_key]["cached_input"] += cit
    TOK["total"]["input"] += it
    TOK["total"]["output"] += ot
    TOK["total"]["cached_input"] += cit


def extract_usage(resp: Any) -> Tuple[int, int, int]:
    """
    Return (input_tokens, output_tokens, cached_input_tokens) from a LangChain response.
    Tries multiple metadata layouts across providers/wrappers. Missing fields default to 0.
    """
    inp = outp = cached = 0

    # Newer LangChain: usage_metadata
    um = getattr(resp, "usage_metadata", None)
    if isinstance(um, dict):
        inp = int(um.get("input_tokens") or um.get("prompt_tokens") or 0)
        outp = int(um.get("output_tokens") or um.get("completion_tokens") or 0)
        cached = int(
            um.get("cache_creation_input_tokens")
            or um.get("cache_read_input_tokens")
            or um.get("prompt_cached_tokens")
            or 0
        )

    # response_metadata.token_usage / usage
    rm = getattr(resp, "response_metadata", None)
    if isinstance(rm, dict):
        tu = rm.get("token_usage") or rm.get("usage")
        if isinstance(tu, dict):
            inp = int(tu.get("input_tokens") or tu.get("prompt_tokens") or inp)
            outp = int(tu.get("output_tokens") or tu.get("completion_tokens") or outp)
            cached = int(
                tu.get("cache_creation_input_tokens")
                or tu.get("cache_read_input_tokens")
                or tu.get("prompt_cached_tokens")
                or cached
            )

    return inp, outp, cached
