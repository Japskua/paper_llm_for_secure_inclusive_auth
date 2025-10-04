import json
import os
from typing import Dict, Optional

from app.utils.tokens import TOK
from app.utils.pricing import compute_cost_usd_per_1M


def finalize_summary(
    output_dir: str,
    pricing: Dict,
    pricing_missing: Optional[str],
    verbose: bool,
) -> None:
    summary = {
        "total_input_tokens": TOK["total"]["input"],
        "total_cached_input_tokens": TOK["total"]["cached_input"],
        "total_output_tokens": TOK["total"]["output"],
        "by_agent": TOK,
    }
    # Compute cost if pricing available
    if pricing_missing:
        summary["cost_computation"] = {
            "status": "pricing_missing",
            "message": pricing_missing,
        }
        total_cost = None
    else:
        cost_details, total_cost = compute_cost_usd_per_1M(pricing, TOK)
        summary["cost_computation"] = {
            "status": "ok",
            "total_cost_usd": total_cost,
            "details": cost_details,
            "pricing_units": "USD per 1M tokens",
        }

    summary_path = os.path.join(output_dir, "tokens_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Finished. See workspace artifacts.")
    if total_cost is not None:
        print(
            "Token usage — "
            f"input: {TOK['total']['input']}, "
            f"cached input: {TOK['total']['cached_input']}, "
            f"output: {TOK['total']['output']}\n"
            f"Estimated cost: ${total_cost:.4f} USD (see {summary_path})"
        )
    else:
        print(
            "Token usage — "
            f"input: {TOK['total']['input']}, "
            f"cached input: {TOK['total']['cached_input']}, "
            f"output: {TOK['total']['output']}\n"
            "Cost not computed: pricing info is missing in environment (see tokens_summary.json)."
        )
