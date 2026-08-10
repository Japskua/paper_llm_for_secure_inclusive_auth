from typing import Any, Dict

_AGENTS = ("tasker", "coder", "evaluator")
_FIELDS = ("input", "output", "cached_input", "reasoning", "calls")


def _blank() -> Dict[str, Dict[str, Any]]:
    d: Dict[str, Dict[str, Any]] = {
        a: {f: 0 for f in _FIELDS} | {"cost_usd": 0.0} for a in _AGENTS
    }
    d["total"] = {f: 0 for f in _FIELDS} | {"cost_usd": 0.0}
    return d


# Cumulative token usage. NOTE: this is module-level state, so exactly one
# generation run may execute per process. run_batch.py enforces that by
# spawning each run as a subprocess.
TOK: Dict[str, Dict[str, Any]] = _blank()

# Upstream providers actually served by OpenRouter during this run. Recorded so
# a "10 identical runs" claim can be checked against the backends used.
PROVIDERS_SEEN: Dict[str, int] = {}

# Model ids OpenRouter actually served, which can differ from the one requested.
# Verifying this is what makes "the same model across all cases" checkable.
MODELS_SEEN: Dict[str, int] = {}

# Exact dated model snapshots served (e.g. openai/gpt-5.6-terra-20260709). The
# model id passed to the API is an alias; this is the version to cite.
MODEL_VERSIONS: Dict[str, int] = {}

# OpenRouter generation ids. LangChain drops OpenRouter's top-level `provider`
# field, so the serving backend is resolved from these ids after the run.
GENERATION_IDS: list = []


def reset() -> None:
    """Clear all counters (used by tests and any in-process reuse)."""
    global TOK
    TOK = _blank()
    PROVIDERS_SEEN.clear()
    MODELS_SEEN.clear()
    MODEL_VERSIONS.clear()
    GENERATION_IDS.clear()


def add_usage(agent: str, usage: Dict[str, Any]) -> None:
    """
    Accumulate one call's usage for a role and the total.
    In single-agent mode, unknown agent labels map to the 'coder' bucket.
    """
    key = agent if agent in _AGENTS else "coder"
    for field in ("input", "output", "cached_input", "reasoning"):
        v = int(usage.get(field) or 0)
        TOK[key][field] += v
        TOK["total"][field] += v

    cost = float(usage.get("cost_usd") or 0.0)
    TOK[key]["cost_usd"] = round(TOK[key]["cost_usd"] + cost, 8)
    TOK["total"]["cost_usd"] = round(TOK["total"]["cost_usd"] + cost, 8)

    TOK[key]["calls"] += 1
    TOK["total"]["calls"] += 1

    provider = usage.get("provider")
    if provider:
        PROVIDERS_SEEN[provider] = PROVIDERS_SEEN.get(provider, 0) + 1

    model = usage.get("model")
    if model:
        MODELS_SEEN[model] = MODELS_SEEN.get(model, 0) + 1

    gen_id = usage.get("generation_id")
    if gen_id:
        GENERATION_IDS.append(gen_id)


def _first_int(*vals) -> int:
    for v in vals:
        if isinstance(v, (int, float)) and v:
            return int(v)
    return 0


def _dig(d: Any, *path) -> Any:
    """Walk nested dicts, returning None if any hop is missing."""
    cur = d
    for k in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def extract_usage(resp: Any) -> Dict[str, Any]:
    """
    Pull usage from a LangChain response across provider/wrapper layouts.

    Returns keys: input, output, cached_input, reasoning, cost_usd, provider, model.

    `reasoning` matters because frontier reasoning models bill reasoning tokens
    as output; counting only visible output understates real cost substantially.
    `cost_usd` comes straight from OpenRouter (usage.include=true) and is
    authoritative — it beats multiplying tokens by a hand-maintained price table.
    """
    um = getattr(resp, "usage_metadata", None) or {}
    rm = getattr(resp, "response_metadata", None) or {}
    tu = rm.get("token_usage") or rm.get("usage") or {}

    inp = _first_int(
        um.get("input_tokens"), um.get("prompt_tokens"),
        tu.get("input_tokens"), tu.get("prompt_tokens"),
    )
    outp = _first_int(
        um.get("output_tokens"), um.get("completion_tokens"),
        tu.get("output_tokens"), tu.get("completion_tokens"),
    )
    cached = _first_int(
        _dig(um, "input_token_details", "cache_read"),
        um.get("cache_read_input_tokens"), um.get("prompt_cached_tokens"),
        _dig(tu, "prompt_tokens_details", "cached_tokens"),
        tu.get("cache_read_input_tokens"), tu.get("prompt_cached_tokens"),
    )
    reasoning = _first_int(
        _dig(um, "output_token_details", "reasoning"),
        um.get("reasoning_tokens"),
        _dig(tu, "completion_tokens_details", "reasoning_tokens"),
        tu.get("reasoning_tokens"),
    )

    cost = None
    for candidate in (
        tu.get("cost"),
        rm.get("cost"),
        _dig(tu, "cost_details", "upstream_inference_cost"),
    ):
        if isinstance(candidate, (int, float)):
            cost = float(candidate)
            break

    return {
        "input": inp,
        "output": outp,
        "cached_input": cached,
        "reasoning": reasoning,
        "cost_usd": cost,
        # LangChain's OpenAI wrapper discards OpenRouter's top-level `provider`,
        # so this is usually None and the backend is resolved from generation_id.
        "provider": rm.get("provider") or rm.get("provider_name"),
        "model": rm.get("model_name") or rm.get("model"),
        "generation_id": rm.get("id"),
    }


def resolve_providers(timeout_s: float = 10.0, limit: int = 200) -> Dict[str, int]:
    """
    Look up which upstream backend served each generation, via OpenRouter's
    /generation endpoint, and record the exact dated model version.

    The endpoint is eventually consistent — a generation just completed returns
    404 for a second or two — so each id gets a couple of retries.

    Best-effort: failures leave the dicts as-is, since this is provenance
    metadata, not experimental data.
    """
    import os
    import time

    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not key or not GENERATION_IDS:
        return dict(PROVIDERS_SEEN)

    try:
        import httpx
    except ImportError:
        return dict(PROVIDERS_SEEN)

    headers = {"Authorization": f"Bearer {key}"}
    with httpx.Client(timeout=timeout_s, headers=headers) as client:
        for gen_id in GENERATION_IDS[:limit]:
            for attempt in (1, 2, 3):
                try:
                    resp = client.get(
                        "https://openrouter.ai/api/v1/generation", params={"id": gen_id}
                    )
                except Exception:
                    break
                if resp.status_code == 404 and attempt < 3:
                    time.sleep(1.5 * attempt)  # generation not yet queryable
                    continue
                if resp.status_code != 200:
                    break
                data = resp.json().get("data") or {}
                name = data.get("provider_name")
                if name:
                    PROVIDERS_SEEN[name] = PROVIDERS_SEEN.get(name, 0) + 1
                # The alias (openai/gpt-5.6-terra) resolves to a dated snapshot
                # (openai/gpt-5.6-terra-20260709). Cite the snapshot.
                slug = data.get("model_permaslug") or data.get("model")
                if slug:
                    MODEL_VERSIONS[slug] = MODEL_VERSIONS.get(slug, 0) + 1
                break
    return dict(PROVIDERS_SEEN)


def cost_is_reported() -> bool:
    """True when the backend returned real cost figures (so we can skip the price table)."""
    return TOK["total"]["cost_usd"] > 0.0
