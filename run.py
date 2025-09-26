import json
import sys
import time
import os
import pathlib
import argparse
from dotenv import load_dotenv
from typing import List, TypedDict, cast
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.exceptions import OutputParserException
from httpx import HTTPError, ReadTimeout
from provider import make_three_llms

# Load secrets from .env
load_dotenv()

# OWN FUNCTIONS


def safe_invoke(llm, messages, who: str, iter_no: int):
    vprint(f"[iter {iter_no}] {who}: invoking")
    try:
        resp = llm.invoke(messages)
        return resp
    except (ReadTimeout, HTTPError) as e:
        print(f"[FATAL] {who} request failed: {e}")
        # Persist a crash marker so you see *something* in the folder
        pathlib.Path(args.output, f"CRASH_{who}_iter{iter_no}.txt").write_text(
            str(e), encoding="utf-8"
        )
        raise
    except Exception as e:
        print(f"[FATAL] {who} unexpected error: {e}")
        pathlib.Path(args.output, f"CRASH_{who}_iter{iter_no}.txt").write_text(
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


# ---- Token accounting helpers ----


def extract_usage(resp) -> tuple[int, int, int]:
    """
    Return (input_tokens, output_tokens, cached_input_tokens).
    We try several LangChain / provider metadata layouts.
    Missing fields default to 0.
    """
    inp = outp = cached = 0

    # Newer LangChain: usage_metadata
    um = getattr(resp, "usage_metadata", None)
    if isinstance(um, dict):
        inp = int(um.get("input_tokens") or um.get("prompt_tokens") or 0)
        outp = int(um.get("output_tokens") or um.get("completion_tokens") or 0)
        # OpenAI (via LC) sometimes exposes:
        cached = int(
            um.get("cache_creation_input_tokens")
            or um.get("cache_read_input_tokens")
            or um.get("prompt_cached_tokens")
            or 0
        )

    # response_metadata.token_usage
    rm = getattr(resp, "response_metadata", None)
    if isinstance(rm, dict):
        tu = rm.get("token_usage") or rm.get("usage")
        if isinstance(tu, dict):
            # Prompt/Input
            inp = int(tu.get("input_tokens") or tu.get("prompt_tokens") or inp)
            outp = int(tu.get("output_tokens") or tu.get("completion_tokens") or outp)
            cached = int(
                tu.get("cache_creation_input_tokens")
                or tu.get("cache_read_input_tokens")
                or tu.get("prompt_cached_tokens")
                or cached
            )

    return inp, outp, cached


# Global token counters (kept in-memory; also logged per-iter)
TOK = {
    "tasker": {"input": 0, "output": 0, "cached_input": 0},
    "coder": {"input": 0, "output": 0, "cached_input": 0},
    "evaluator": {"input": 0, "output": 0, "cached_input": 0},
    "total": {"input": 0, "output": 0, "cached_input": 0},
}


def add_usage(agent: str, it: int, ot: int, cit: int):
    TOK[agent]["input"] += it
    TOK[agent]["output"] += ot
    TOK[agent]["cached_input"] += cit
    TOK["total"]["input"] += it
    TOK["total"]["output"] += ot
    TOK["total"]["cached_input"] += cit


def _getenv_float(name: str):
    v = os.getenv(name)
    if not v:
        return None
    try:
        return float(v)
    except Exception:
        return None


def _resolve_rate_per_1M(primary_key: str):
    """
    Resolve a price per 1M tokens.
    """
    per_m = _getenv_float(primary_key)
    if per_m is not None:
        return per_m
    return None


def load_pricing():
    """
    Load pricing (USD per 1M tokens). Supports:
      - Global defaults: PRICE_INPUT_PER_1M, PRICE_CACHED_INPUT_PER_1M, PRICE_OUTPUT_PER_1M
      - Per-role overrides: PRICE_{ROLE}_{TYPE}_PER_1M
      - Fallback to *_PER_1K auto-scaled ×1000
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

    pr = {
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


def compute_cost_usd_per_1M(pricing, usage_by_agent):
    """
    Compute cost given pricing dict (per 1M tokens) and usage_by_agent like TOK.
    Includes cached_input tokens when a rate is provided (else falls back to default.cached_in or 0).
    """

    def rate(role: str, kind: str):  # kind: 'in' | 'cached_in' | 'out'
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


# ======================
# CLI ARGUMENTS
# ======================
parser = argparse.ArgumentParser(
    description="Run multi-agent LLM evaluation loop for password recovery experiment."
)

parser.add_argument("--tasker", required=True, help="Path to prompt_tasker.txt")
parser.add_argument("--coder", required=True, help="Path to prompt_coder.txt")
parser.add_argument(
    "--eval", dest="eval_", required=True, help="Path to prompt_eval.txt"
)
parser.add_argument("--requirements", required=True, help="Path to requirements.md")
parser.add_argument("--output", required=True, help="Output folder for artifacts")
parser.add_argument(
    "--criteria", required=False, help="Optional path to inclusivity rubric file"
)
parser.add_argument(
    "--max-iters",
    type=int,
    default=8,
    help="Maximum number of loop iterations (default: 8)",
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Verbose debug output (show prompts, responses, and timing).",
)

args = parser.parse_args()


# Printer
def vprint(*msg):
    if args.verbose:
        # nice timestamped prefix
        import datetime as _dt

        print(f"[{_dt.datetime.now().strftime('%H:%M:%S')}]", *msg, flush=True)


vprint(
    "CONFIG:",
    f"tasker={args.tasker}",
    f"coder={args.coder}",
    f"eval={args.eval_}",
    f"requirements={args.requirements}",
    f"output={args.output}",
    f"criteria={'(none)' if not args.criteria else args.criteria}",
    f"max_iters={args.max_iters}",
)

# Validate files
for p in [args.tasker, args.coder, args.eval_, args.requirements]:
    if not pathlib.Path(p).is_file():
        raise FileNotFoundError(f"Required file not found: {p}")

if args.criteria and not pathlib.Path(args.criteria).is_file():
    raise FileNotFoundError(f"Inclusivity criteria file not found: {args.criteria}")

# Ensure output folder exists
os.makedirs(args.output, exist_ok=True)


# ======================
# SYSTEM PROMPTS
# ======================

# Load prompt texts
SYSTEM_TASKER = pathlib.Path(args.tasker).read_text(encoding="utf-8")
SYSTEM_CODER = pathlib.Path(args.coder).read_text(encoding="utf-8")
SYSTEM_EVAL = pathlib.Path(args.eval_).read_text(encoding="utf-8")
requirements = pathlib.Path(args.requirements).read_text(encoding="utf-8")

INCLUSIVITY_CRITERIA = None
if args.criteria:
    INCLUSIVITY_CRITERIA = pathlib.Path(args.criteria).read_text(encoding="utf-8")


# ======================
# CONFIG
# ======================
MAX_ITERS = args.max_iters


# ======================
# MODELS
# ======================
llm_tasker, llm_coder, llm_eval = make_three_llms(temperature=0.0)


# Try to print model names if available (LangChain wrappers vary)
def _model_name(llm):
    return (
        getattr(llm, "model_name", None) or getattr(llm, "model", None) or "(unknown)"
    )


vprint(
    "LLMs:",
    f"TASKER={_model_name(llm_tasker)}",
    f"CODER={_model_name(llm_coder)}",
    f"EVALUATOR={_model_name(llm_eval)}",
)

pricing, pricing_missing = load_pricing()
if args.verbose:
    if pricing_missing:
        vprint("PRICING:", pricing_missing)
    else:
        vprint(
            "PRICING (USD per 1M):",
            f"default in={pricing['default']['in']}, cached_in={pricing['default']['cached_in']}, out={pricing['default']['out']}",
            f"tasker in={pricing['tasker']['in']}, cached_in={pricing['tasker']['cached_in']}, out={pricing['tasker']['out']}",
            f"coder in={pricing['coder']['in']}, cached_in={pricing['coder']['cached_in']}, out={pricing['coder']['out']}",
            f"evaluator in={pricing['evaluator']['in']}, cached_in={pricing['evaluator']['cached_in']}, out={pricing['evaluator']['out']}",
        )


# ======================
# STATE SCHEMA
# ======================
class State(TypedDict):
    code_html: str
    task_list: List[str]
    evaluator_md: str
    done: bool
    iter: int


init_code = """<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <title>Recovery Demo</title>
</head>
<body>
  <main id='app'>Loading…</main>
  <script>/* TODO */</script>
</body>
</html>
"""

state: State = {
    "code_html": init_code,
    "task_list": [],
    "evaluator_md": "",
    "done": False,
    "iter": 0,
}


# ======================
# NODES
# ======================
def tasker_node(state: State) -> State:
    user_msg = f"""Requirements:
        {requirements}
        Evaluator feedback:
        {state.get('evaluator_md','(none yet)')}
        Current tasks: {json.dumps(state.get('task_list', []), ensure_ascii=False)}
    """
    # Get some debug output
    vprint(f"[iter {state.get('iter', '?')}] TASKER: invoking")

    resp = safe_invoke(
        llm_tasker,
        [
            {"role": "system", "content": SYSTEM_TASKER},
            {"role": "user", "content": user_msg},
        ],
        "TASKER",
        int(state.get("iter", 0)),
    )
    # Token usage
    it, ot, cit = extract_usage(resp)
    add_usage("tasker", it, ot, cit)
    if args.verbose:
        vprint(
            f"[iter {state.get('iter','?')}] TASKER tokens: input={it}, cached_input={cit}, output={ot}"
        )

    # Normalize resp.content to str
    text = normalize_content(resp.content)
    if args.verbose:
        # show only first 400 chars to avoid spam
        preview = (text[:400] + "…") if len(text) > 400 else text
        vprint(f"[iter {state.get('iter','?')}] TASKER output (preview): {preview}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        vprint(f"[iter {state.get('iter','?')}] TASKER JSON ERROR. Raw:\n{text}")
        raise ValueError(f"Tasker did not return valid JSON. Got:\n{text}") from e

    state["task_list"] = data.get("task_list", [])
    state["done"] = bool(data.get("done", False))
    vprint(
        f"[iter {state.get('iter','?')}] TASKER: tasks={len(state['task_list'])}, done={state['done']}"
    )
    return state


def coder_node(state: State) -> State:
    tasks_str = "\n".join(f"- {t}" for t in state["task_list"]) or "(no tasks)"
    user_msg = f"""Requirements (for reference): {requirements}
        Tasks to implement now:
        {tasks_str}

        Current index.html (edit in-place and return FULL FILE):
        {state['code_html']}
    """
    # Some debugging
    vprint(
        f"[iter {state.get('iter','?')}] CODER: invoking with {len(state['task_list'])} task(s)"
    )

    resp = safe_invoke(
        llm_coder,
        [
            {"role": "system", "content": SYSTEM_CODER},
            {"role": "user", "content": user_msg},
        ],
        "CODER",
        iter_no=state.get("iter", 0),
    )
    # Token usage
    it, ot, cit = extract_usage(resp)
    add_usage("coder", it, ot, cit)
    if args.verbose:
        vprint(
            f"[iter {state.get('iter','?')}] CODER tokens: input={it}, cached_input={cit}, output={ot}"
        )

    # Normalize resp.content to str
    text = normalize_content(resp.content)

    # Extract between <FILE> ... </FILE>
    start = text.find("<FILE>")
    end = text.find("</FILE>")
    code = text[start + 6 : end] if start != -1 and end != -1 else text
    state["code_html"] = code

    # --- Save artifacts ---
    # Latest
    pathlib.Path(args.output, "index.html").write_text(
        state["code_html"], encoding="utf-8"
    )

    # Versioned (use the current iteration from state; default to 0 if missing)
    iter_no = int(state.get("iter", 0))
    versioned_name = f"index_iter{iter_no}.html"
    pathlib.Path(args.output, versioned_name).write_text(
        state["code_html"], encoding="utf-8"
    )

    if args.verbose:
        vprint(
            f"[iter {iter_no}] CODER: wrote index.html and index_iter{iter_no}.html "
            f"(chars={len(state['code_html'])})"
        )

    return state


def evaluator_node(state: State) -> State:
    user_msg = f"""Evaluate the current artifact.
        Requirements:
        {requirements}

        index.html:
        {state['code_html']}
    """
    # Some debugging
    vprint(f"[iter {state.get('iter','?')}] EVALUATOR: invoking")

    resp = safe_invoke(
        llm_eval,
        [
            {"role": "system", "content": SYSTEM_EVAL},
            {"role": "user", "content": user_msg},
        ],
        "EVALUATOR",
        int(state.get("iter", 0)),
    )

    # Token usage
    it, ot, cit = extract_usage(resp)
    add_usage("evaluator", it, ot, cit)
    if args.verbose:
        vprint(
            f"[iter {state.get('iter','?')}] EVALUATOR tokens: input={it}, cached_input={cit}, output={ot}"
        )

    # Normalize resp.content to str
    text = normalize_content(resp.content)

    state["evaluator_md"] = text

    # --- Save artifacts ---
    # Latest
    pathlib.Path(args.output, "evaluator_report.md").write_text(text, encoding="utf-8")
    # Versioned
    iter_no = int(state.get("iter", 0))
    versioned_name = f"evaluator_report_iter{iter_no}.md"
    pathlib.Path(args.output, versioned_name).write_text(text, encoding="utf-8")

    # Parse DECISION
    decision = "FAIL"
    for line in text.splitlines():
        if line.strip().upper().startswith("DECISION"):
            if "PASS" in line.upper():
                decision = "PASS"
            break

    if args.verbose:
        # show a couple of tasks to confirm flow
        preview_tasks = state.get("task_list", [])[:3]
        vprint(
            f"[iter {iter_no}] EVALUATOR: decision={decision}, "
            f"current tasks sample={preview_tasks}"
        )

    if decision == "PASS":
        state["done"] = True
        state["task_list"] = []
    else:
        # Parse NEW_TASKS
        tasks = []
        capture = False
        for ln in text.splitlines():
            if ln.strip().upper().startswith("NEW_TASKS"):
                capture = True
                continue
            if capture:
                if ln.strip().startswith(("-", "1.", "2.", "3.")):
                    clean = (
                        ln.lstrip("- ").split(".", 1)[-1].strip()
                        if ln.strip()[0].isdigit()
                        else ln.lstrip("- ").strip()
                    )
                    tasks.append(clean)
                elif ln.strip() == "":
                    break
        state["task_list"] = tasks or state["task_list"]
        if args.verbose:
            vprint(
                f"[iter {iter_no}] EVALUATOR: parsed NEW_TASKS={len(state['task_list'])}"
            )
    return state


# ======================
# GRAPH
# ======================
g = StateGraph(State)
g.add_node("tasker", tasker_node)
g.add_node("coder", coder_node)
g.add_node("evaluator", evaluator_node)

# static edges
g.add_edge("tasker", "coder")
g.add_edge("coder", "evaluator")


# conditional branch after evaluator
def _next_after_evaluator(state: State) -> str:
    return "end" if state.get("done") else "tasker"


g.add_conditional_edges(
    "evaluator",
    _next_after_evaluator,
    {
        "end": END,
        "tasker": "tasker",
    },
)

g.set_entry_point("tasker")

app = g.compile()

# ======================
# RUN LOOP
# ======================
logf = open(os.path.join(args.output, "log.jsonl"), "a", encoding="utf-8")
statef = open(os.path.join(args.output, "state.jsonl"), "a", encoding="utf-8")
# Token usage tracking
prev_totals = {"input": 0, "output": 0}

print(
    "Starting loop… (if this hangs, a network call is stuck; use --verbose and check CRASH_* files)"
)
for i in range(MAX_ITERS):
    vprint(f"==== Iteration {i+1}/{MAX_ITERS} ====")
    t0 = time.time()
    state["iter"] = i + 1
    state = cast(State, app.invoke(state))  # safe cast
    t1 = time.time()
    dur = round(t1 - t0, 2)

    # Compute iteration deltas
    delta_in = TOK["total"]["input"] - prev_totals["input"]
    delta_out = TOK["total"]["output"] - prev_totals["output"]
    prev_totals["input"] = TOK["total"]["input"]
    prev_totals["output"] = TOK["total"]["output"]

    vprint(
        f"[iter {i+1}] cycle duration: {dur}s, "
        f"done={state['done']}, tasks={len(state['task_list'])}, "
        f"tokens(in={delta_in}, out={delta_out})"
    )

    # Minimal log (performance + summary)
    logf.write(
        json.dumps(
            {
                "iter": i + 1,
                "done": state["done"],
                "task_list": state["task_list"],
                "duration_s": dur,
                "tokens_iter": {"input": delta_in, "output": delta_out},
                "tokens_cumulative": {
                    "input": TOK["total"]["input"],
                    "output": TOK["total"]["output"],
                },
                "tokens_by_agent": TOK,  # snapshot
            },
            ensure_ascii=False,
        )
        + "\n"
    )
    logf.flush()

    # Full state snapshot
    statef.write(json.dumps(state, ensure_ascii=False) + "\n")
    statef.flush()

    print(f"Iter {i+1} done. done={state['done']}, tasks={len(state['task_list'])}")
    if state["done"]:
        break

# Close the logging file handles
logf.close()
statef.close()


# ---- Final token & cost summary file ----
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


summary_path = os.path.join(args.output, "tokens_summary.json")
with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

print("Finished. See workspace artifacts.")

if total_cost is not None:
    print(
        "Token usage — "
        f"input: {TOK['total']['input']}, "
        f"cached input: {TOK['total']['cached_input']}, "
        f"output: {TOK['total']['output']}.\n"
        f"Estimated cost: ${total_cost:.4f} USD (see {summary_path})"
    )
else:
    print(
        "Token usage — "
        f"input: {TOK['total']['input']}, "
        f"cached input: {TOK['total']['cached_input']}, "
        f"output: {TOK['total']['output']}.\n"
        "Cost not computed: pricing info is missing in environment (see tokens_summary.json)."
    )
