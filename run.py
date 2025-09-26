import json
import sys
import time
import os
import pathlib
import argparse
from dotenv import load_dotenv
from typing import Dict, Any, List, TypedDict, cast
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from provider import make_three_llms

# Load secrets from .env
load_dotenv()


def normalize_content(content) -> str:
    """Normalize LangChain response content to a plain string."""
    if isinstance(content, list):
        return "".join(
            part.get("text", "") if isinstance(part, dict) else str(part)
            for part in content
        )
    return str(content)


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

args = parser.parse_args()

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
    resp = llm_tasker.invoke(
        [
            {"role": "system", "content": SYSTEM_TASKER},
            {"role": "user", "content": user_msg},
        ]
    )
    # Normalize resp.content to str
    text = normalize_content(resp.content)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Tasker did not return valid JSON. Got:\n{text}") from e

    state["task_list"] = data.get("task_list", [])
    state["done"] = bool(data.get("done", False))
    return state


def coder_node(state: State) -> State:
    tasks_str = "\n".join(f"- {t}" for t in state["task_list"]) or "(no tasks)"
    user_msg = f"""Requirements (for reference): {requirements}
        Tasks to implement now:
        {tasks_str}

        Current index.html (edit in-place and return FULL FILE):
        {state['code_html']}
    """
    resp = llm_coder.invoke(
        [
            {"role": "system", "content": SYSTEM_CODER},
            {"role": "user", "content": user_msg},
        ]
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

    return state


def evaluator_node(state: State) -> State:
    user_msg = f"""Evaluate the current artifact.
        Requirements:
        {requirements}

        index.html:
        {state['code_html']}
    """
    resp = llm_eval.invoke(
        [
            {"role": "system", "content": SYSTEM_EVAL},
            {"role": "user", "content": user_msg},
        ]
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

for i in range(MAX_ITERS):
    t0 = time.time()
    state["iter"] = i + 1
    state = cast(State, app.invoke(state))  # safe cast
    t1 = time.time()

    # Minimal log (performance + summary)
    logf.write(
        json.dumps(
            {
                "iter": i + 1,
                "done": state["done"],
                "task_list": state["task_list"],
                "duration_s": round(t1 - t0, 2),
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

logf.close()
statef.close()
print("Finished. See workspace artifacts.")
