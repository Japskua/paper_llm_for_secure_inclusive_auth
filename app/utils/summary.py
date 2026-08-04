import json
import os
from typing import Any, Dict, Optional

from app.utils.tokens import TOK, cost_is_reported
from app.utils.pricing import compute_cost_usd_per_1M


def finalize_summary(
    output_dir: str,
    pricing: Dict,
    pricing_missing: Optional[str],
    verbose: bool,
    run_meta: Optional[Dict[str, Any]] = None,
) -> None:
    summary: Dict[str, Any] = {
        "total_input_tokens": TOK["total"]["input"],
        "total_cached_input_tokens": TOK["total"]["cached_input"],
        "total_output_tokens": TOK["total"]["output"],
        "total_reasoning_tokens": TOK["total"]["reasoning"],
        "total_calls": TOK["total"]["calls"],
        "by_agent": TOK,
    }
    if run_meta:
        summary["run"] = run_meta

    # Prefer cost reported by the backend (OpenRouter usage accounting). It
    # accounts for reasoning tokens and per-provider rates that a hand-kept
    # price table in .env cannot track.
    if cost_is_reported():
        total_cost = TOK["total"]["cost_usd"]
        summary["cost_computation"] = {
            "status": "reported_by_provider",
            "total_cost_usd": total_cost,
            "by_agent_usd": {
                a: TOK[a]["cost_usd"] for a in ("tasker", "coder", "evaluator")
            },
            "source": "OpenRouter usage accounting (usage.include=true)",
        }
    elif pricing_missing:
        summary["cost_computation"] = {
            "status": "pricing_missing",
            "message": pricing_missing,
        }
        total_cost = None
    else:
        cost_details, total_cost = compute_cost_usd_per_1M(pricing, TOK)
        summary["cost_computation"] = {
            "status": "estimated_from_env_pricing",
            "total_cost_usd": total_cost,
            "details": cost_details,
            "pricing_units": "USD per 1M tokens",
            "caveat": (
                "Reasoning tokens are billed as output; verify the output rate "
                "covers them for this model."
            ),
        }

    summary_path = os.path.join(output_dir, "tokens_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Finished. See workspace artifacts.")
    usage_line = (
        "Token usage — "
        f"input: {TOK['total']['input']}, "
        f"cached input: {TOK['total']['cached_input']}, "
        f"output: {TOK['total']['output']} "
        f"(of which reasoning: {TOK['total']['reasoning']})"
    )
    if total_cost is not None:
        print(f"{usage_line}\nCost: ${total_cost:.4f} USD (see {summary_path})")
    else:
        print(
            f"{usage_line}\n"
            "Cost not computed: pricing info is missing in environment "
            f"(see {summary_path})."
        )
