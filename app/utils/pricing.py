import os
from typing import Dict, Tuple, Optional


def _getenv_float(name: str) -> Optional[float]:
    v = os.getenv(name)
    if not v:
        return None
    try:
        return float(v)
    except Exception:
        return None


def _resolve_rate_per_1M(primary_key: str) -> Optional[float]:
    """
    Resolve a price per 1M tokens from env.
    """
    per_m = _getenv_float(primary_key)
    if per_m is not None:
        return per_m
    return None


def load_pricing() -> Tuple[Dict[str, Dict[str, Optional[float]]], Optional[str]]:
    """
    Load pricing (USD per 1M tokens). Supports:
      - Global defaults: PRICE_INPUT_PER_1M, PRICE_CACHED_INPUT_PER_1M, PRICE_OUTPUT_PER_1M
      - Per-role overrides: PRICE_{ROLE}_{TYPE}_PER_1M
    Returns: (pricing_dict, missing_reason_str or None)
    """

    def role_rates(role: str):
        rin = _resolve_rate_per_1M(f"PRICE_{role.upper()}_INPUT_PER_1M")
        rcin = _resolve_rate_per_1M(f"PRICE_{role.upper()}_CACHED_INPUT_PER_1M")
        rout = _resolve_rate_per_1M(f"PRICE_{role.upper()}_OUTPUT_PER_1M")
        return rin, rcin, rout

    default_in = _resolve_rate_per_1M("PRICE_INPUT_PER_1M")
    default_cin = _resolve_rate_per_1M("PRICE_CACHED_INPUT_PER_1M")
    default_out = _resolve_rate_per_1M("PRICE_OUTPUT_PER_1M")

    pr: Dict[str, Dict[str, Optional[float]]] = {
        "default": {"in": default_in, "cached_in": default_cin, "out": default_out},
        "tasker": {"in": None, "cached_in": None, "out": None},
        "coder": {"in": None, "cached_in": None, "out": None},
        "evaluator": {"in": None, "cached_in": None, "out": None},
    }
    for role in ("tasker", "coder", "evaluator"):
        ri, rci, ro = role_rates(role)
        pr[role]["in"] = ri
        pr[role]["cached_in"] = rci
        pr[role]["out"] = ro

    # Do we have enough info? At least defaults with any nonzero, or any role override present
    have_defaults = any(
        [(default_in or 0) > 0, (default_cin or 0) > 0, (default_out or 0) > 0]
    )
    have_any_role = any(
        (pr[r]["in"] or pr[r]["cached_in"] or pr[r]["out"])
        for r in ("tasker", "coder", "evaluator")
    )

    if not have_defaults and not have_any_role:
        return pr, "Pricing info is missing from environment; could not compute cost."

    return pr, None


def compute_cost_usd_per_1M(
    pricing: Dict[str, Dict[str, Optional[float]]], usage_by_agent: Dict
) -> Tuple[Dict, float]:
    """
    Compute cost given pricing dict (per 1M tokens) and usage_by_agent like TOK.
    Includes cached_input tokens when a rate is provided (else falls back to default.cached_in or 0).
    """

    def rate(role: str, kind: str) -> float:  # kind: 'in' | 'cached_in' | 'out'
        r = pricing.get(role, {})
        val = r.get(kind)
        if val is None:
            val = pricing["default"].get(kind)
        return float(val or 0.0)

    details = {}
    total = 0.0
    for role in ("tasker", "coder", "evaluator"):
        it = usage_by_agent[role]["input"]
        cit = usage_by_agent[role]["cached_input"]
        ot = usage_by_agent[role]["output"]

        r_in = rate(role, "in")
        r_cin = rate(role, "cached_in")
        r_out = rate(role, "out")

        cost = (
            (it / 1_000_000.0) * r_in
            + (cit / 1_000_000.0) * r_cin
            + (ot / 1_000_000.0) * r_out
        )
        details[role] = {
            "input_tokens": it,
            "cached_input_tokens": cit,
            "output_tokens": ot,
            "rate_input_per_1M": r_in,
            "rate_cached_input_per_1M": r_cin,
            "rate_output_per_1M": r_out,
            "cost_usd": round(cost, 6),
        }
        total += cost
    return details, round(total, 6)
