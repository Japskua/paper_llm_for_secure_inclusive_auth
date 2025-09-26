import json
import sys
import time
import os
import pathlib
import argparse
from dotenv import load_dotenv
from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from provider import make_three_llms

# Load secrets from .env
load_dotenv()

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
MAX_ITERS = 8

# Toggle inclusivity for Case 3/4
INCLUSIVITY = False  # set True for inclusivity cases

# Paths
RUN_DIR = "workspace/run_001"
REQ_PATH = "experiments/requirements_no_inclusion.md"  # change for Case 3/4

os.makedirs(RUN_DIR, exist_ok=True)

# ======================
# LOAD REQUIREMENTS
# ======================
requirements = pathlib.Path(REQ_PATH).read_text()

# ======================
# MODELS
# ======================
llm_tasker, llm_coder, llm_eval = make_three_llms(temperature=0.0)


INCLUSIVITY_NOTE = (
    ""
    if not INCLUSIVITY
    else """
Note: Apply the Inclusivity Rubric rigorously; include INCLUSIVITY_SCORES.
"""
)


# ======================
# STATE
# ======================
class S(dict):
    """State wrapper so we can pass dict-like state through LangGraph."""


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

state = S(code_html=init_code, task_list=[], evaluator_md="", done=False, iter=0)


# ======================
# NODES
# ======================
def tasker_node(s: S):
    user_msg = f"""Requirements:
{requirements}
Evaluator feedback:
{s.get('evaluator_md','(none yet)')}
Current tasks: {json.dumps(s.get('task_list', []), ensure_ascii=False)}
"""
    resp = llm_tasker.invoke(
        [
            {"role": "system", "content": SYSTEM_TASKER},
            {"role": "user", "content": user_msg},
        ]
    )
    data = json.loads(resp.content)
    s["task_list"] = data.get("task_list", [])
    s["done"] = bool(data.get("done", False))
    return s


def coder_node(s: S):
    tasks_str = "\n".join(f"- {t}" for t in s["task_list"]) or "(no tasks)"
    user_msg = f"""Requirements (for reference): {requirements}
    Tasks to implement now:
    {tasks_str}

    Current index.html (edit in-place and return FULL FILE):
    {s['code_html']}
    """
    resp = llm_coder.invoke(
        [
            {"role": "system", "content": SYSTEM_CODER},
            {"role": "user", "content": user_msg},
        ]
    ).content
    # Extract between <FILE> ... </FILE>
    start = resp.find("<FILE>")
    end = resp.find("</FILE>")
    code = resp[start + 6 : end] if start != -1 and end != -1 else resp
    s["code_html"] = code
    pathlib.Path(RUN_DIR, "index.html").write_text(s["code_html"])
    return s


def evaluator_node(s: S):
    user_msg = f"""Evaluate the current artifact.

{INCLUSIVITY_NOTE}

Requirements:
{requirements}

index.html:
{s['code_html']}
"""
    resp = llm_eval.invoke(
        [
            {"role": "system", "content": SYSTEM_EVAL},
            {"role": "user", "content": user_msg},
        ]
    ).content
    s["evaluator_md"] = resp
    pathlib.Path(RUN_DIR, "evaluator_report.md").write_text(resp)

    # Parse DECISION
    decision = "FAIL"
    for line in resp.splitlines():
        if line.strip().upper().startswith("DECISION"):
            if "PASS" in line.upper():
                decision = "PASS"
            break

    if decision == "PASS":
        s["done"] = True
        s["task_list"] = []
    else:
        # Parse NEW_TASKS
        tasks = []
        capture = False
        for ln in resp.splitlines():
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
        s["task_list"] = tasks or s["task_list"]
    return s


# ======================
# GRAPH
# ======================
g = StateGraph(S)
g.add_node("tasker", tasker_node)
g.add_node("coder", coder_node)
g.add_node("evaluator", evaluator_node)

g.add_edge("tasker", "coder")
g.add_edge("coder", "evaluator")
g.add_edge("evaluator", "tasker")

g.set_entry_point("tasker")
g.set_finish_point(END)

app = g.compile()

# ======================
# RUN LOOP
# ======================
logf = open(os.path.join(RUN_DIR, "log.jsonl"), "a", encoding="utf-8")

for i in range(MAX_ITERS):
    t0 = time.time()
    state["iter"] = i + 1
    state = app.invoke(state)
    t1 = time.time()
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
    print(f"Iter {i+1} done. done={state['done']}, tasks={len(state['task_list'])}")
    if state["done"]:
        break

logf.close()
print("Finished. See workspace artifacts.")
