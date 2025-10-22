import json
import time
import os
import pathlib
from typing import List, TypedDict, cast

from langgraph.graph import StateGraph, END

from app.constants import INIT_CODE
from app.utils.io import vprint, safe_invoke, normalize_content, set_args
from app.utils.tokens import TOK, add_usage, extract_usage
from app.utils.pricing import load_pricing
from app.utils.summary import finalize_summary
from provider import make_three_llms


class State(TypedDict):
    code_tsx: str
    task_list: List[str]
    evaluator_md: str
    done: bool
    iter: int
    step: int


def run_multi(args) -> None:
    """
    Multi-agent Tasker → Coder → Evaluator loop, unchanged behavior from original run.py.
    """
    # Make io utils aware of args for vprint/safe_invoke
    set_args(args)

    vprint(
        "CONFIG (multi):",
        f"tasker={args.tasker}",
        f"coder={args.coder}",
        f"eval={args.eval_}",
        f"requirements={args.requirements}",
        f"output={args.output}",
        f"criteria={'(none)' if not args.criteria else args.criteria}",
        f"max_iters={args.max_iters}",
    )

    # Load prompt texts
    SYSTEM_TASKER = pathlib.Path(args.tasker).read_text(encoding="utf-8")
    SYSTEM_CODER = pathlib.Path(args.coder).read_text(encoding="utf-8")
    SYSTEM_EVAL = pathlib.Path(args.eval_).read_text(encoding="utf-8")
    requirements = pathlib.Path(args.requirements).read_text(encoding="utf-8")

    INCLUSIVITY_CRITERIA = None
    if args.criteria:
        INCLUSIVITY_CRITERIA = pathlib.Path(args.criteria).read_text(encoding="utf-8")

    MAX_ITERS = args.max_iters

    # MODELS
    llm_tasker, llm_coder, llm_eval = make_three_llms(temperature=0.0)

    # Try to print model names if available (LangChain wrappers vary)
    def _model_name(llm):
        return (
            getattr(llm, "model_name", None)
            or getattr(llm, "model", None)
            or "(unknown)"
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

    # Initial state
    state: State = {
        "code_tsx": INIT_CODE,
        "task_list": [],
        "evaluator_md": "",
        "done": False,
        "iter": 0,
        "step": 0,
    }

    # NODES
    def tasker_node(state: State) -> State:
        user_msg = f"""Requirements:
        {requirements}
        Evaluator feedback:
        {state.get('evaluator_md','(none yet)')}
        Current tasks: {json.dumps(state.get('task_list', []), ensure_ascii=False)}
        """
        # Debug
        state["step"] = int(state.get("step", 0)) + 1
        prefix = f"[iter {state.get('iter','?')} | step {state.get('step','?')}]"
        vprint(f"{prefix} TASKER: invoking")
        resp = safe_invoke(
            llm_tasker,
            [
                {"role": "system", "content": SYSTEM_TASKER},
                {"role": "user", "content": user_msg},
            ],
            "TASKER",
            int(state.get("iter", 0)),
        )
        # Tokens
        it, ot, cit = extract_usage(resp)
        add_usage("tasker", it, ot, cit)
        if args.verbose:
            vprint(
                f"{prefix} TASKER tokens: input={it}, cached_input={cit}, output={ot}"
            )

        text = normalize_content(resp.content)
        if args.verbose:
            preview = (text[:400] + "…") if len(text) > 400 else text
            vprint(f"{prefix} TASKER output (preview): {preview}")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            vprint(f"{prefix} TASKER JSON ERROR. Raw:\n{text}")
            raise ValueError(f"Tasker did not return valid JSON. Got:\n{text}") from e

        new_list = data.get("task_list", [])
        # Evaluator is authoritative for 'done'; do not modify state['done'] here.
        if new_list:
            state["task_list"] = new_list
        else:
            # If Tasker returns empty tasks, retain existing tasks (e.g., from Evaluator NEW_TASKS)
            state["task_list"] = state.get("task_list", [])
        vprint(f"{prefix} TASKER: effective tasks={len(state['task_list'])}")

        # Write Tasker reports (latest and per-iteration)
        iter_no = int(state.get("iter", 0))
        step_no = int(state.get("step", 0))
        raw_count = len(new_list)
        eff_count = len(state["task_list"])
        report_md_lines = [
            f"# TASKER REPORT — Iteration {iter_no} · Step {step_no}",
            "",
            "## SUMMARY",
            f"- Raw tasks from Tasker: {raw_count}",
            f"- Effective task_list after retention: {eff_count}",
            "- Note: Evaluator decides termination; Tasker.done is ignored.",
            "",
            "## RAW_OUTPUT",
            "```",
            text,
            "```",
            "",
            "## PARSED_TASKS",
        ]
        if state["task_list"]:
            report_md_lines.extend([f"- {t}" for t in state["task_list"]])
        else:
            report_md_lines.append("(none)")
        report_md = "\n".join(report_md_lines)

        latest_path = pathlib.Path(args.output, "tasker_report.md")
        versioned_path = pathlib.Path(args.output, f"tasker_report_iter{iter_no}.md")
        latest_path.write_text(report_md, encoding="utf-8")
        if not versioned_path.exists():
            versioned_path.write_text(report_md, encoding="utf-8")
            if args.verbose:
                vprint(
                    f"{prefix} TASKER: wrote tasker_report.md and {versioned_path.name}"
                )
        else:
            if args.verbose:
                vprint(
                    f"{prefix} TASKER: versioned exists, skipping overwrite of {versioned_path.name}"
                )

        return state

    def coder_node(state: State) -> State:
        tasks_str = "\n".join(f"- {t}" for t in state["task_list"]) or "(no tasks)"
        user_msg = f"""Requirements (for reference): {requirements}
        Tasks to implement now:
        {tasks_str}

        Current app.ts (edit in-place and return FULL FILE):
        {state['code_tsx']}
        """
        state["step"] = int(state.get("step", 0)) + 1
        prefix = f"[iter {state.get('iter','?')} | step {state.get('step','?')}]"
        vprint(f"{prefix} CODER: invoking with {len(state['task_list'])} task(s)")

        resp = safe_invoke(
            llm_coder,
            [
                {"role": "system", "content": SYSTEM_CODER},
                {"role": "user", "content": user_msg},
            ],
            "CODER",
            iter_no=state.get("iter", 0),
        )
        it, ot, cit = extract_usage(resp)
        add_usage("coder", it, ot, cit)
        if args.verbose:
            vprint(
                f"{prefix} CODER tokens: input={it}, cached_input={cit}, output={ot}"
            )

        text = normalize_content(resp.content)
        start = text.find("<FILE>")
        end = text.find("</FILE>")
        code = text[start + 6 : end] if start != -1 and end != -1 else text
        state["code_tsx"] = code

        # Save artifacts
        pathlib.Path(args.output, "app.ts").write_text(
            state["code_tsx"], encoding="utf-8"
        )
        iter_no = int(state.get("iter", 0))
        versioned_name = f"code_iter{iter_no}.tsx"
        pathlib.Path(args.output, versioned_name).write_text(
            state["code_tsx"], encoding="utf-8"
        )
        if args.verbose:
            vprint(
                f"{prefix} CODER: wrote app.ts and code_iter{iter_no}.tsx (chars={len(state['code_tsx'])})"
            )
        return state

    def evaluator_node(state: State) -> State:
        user_msg = f"""Evaluate the current artifact.
        Requirements:
        {requirements}

        app.ts:
        {state['code_tsx']}
        """
        state["step"] = int(state.get("step", 0)) + 1
        prefix = f"[iter {state.get('iter','?')} | step {state.get('step','?')}]"
        vprint(f"{prefix} EVALUATOR: invoking")
        resp = safe_invoke(
            llm_eval,
            [
                {"role": "system", "content": SYSTEM_EVAL},
                {"role": "user", "content": user_msg},
            ],
            "EVALUATOR",
            int(state.get("iter", 0)),
        )
        it, ot, cit = extract_usage(resp)
        add_usage("evaluator", it, ot, cit)
        if args.verbose:
            vprint(
                f"{prefix} EVALUATOR tokens: input={it}, cached_input={cit}, output={ot}"
            )

        text = normalize_content(resp.content)
        state["evaluator_md"] = text

        pathlib.Path(args.output, "evaluator_report.md").write_text(
            text, encoding="utf-8"
        )
        iter_no = int(state.get("iter", 0))
        versioned_name = f"evaluator_report_iter{iter_no}.md"
        pathlib.Path(args.output, versioned_name).write_text(text, encoding="utf-8")

        decision = _parse_decision(text)

        if args.verbose:
            preview_tasks = state.get("task_list", [])[:3]
            vprint(
                f"{prefix} EVALUATOR: parsed decision={decision}, current tasks sample={preview_tasks}"
            )

        if decision == "PASS":
            state["done"] = True
            state["task_list"] = []
        else:
            # Evaluator is authoritative: FAIL means we are not done.
            state["done"] = False

            # Parse NEW_TASKS and filter out sentinel non-tasks.
            def _is_sentinel_task(s: str) -> bool:
                return s.strip().lower() in {"none", "none.", "n/a", "no tasks", ""}

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
                        if not _is_sentinel_task(clean):
                            tasks.append(clean)
                    elif ln.strip() == "":
                        break
            # Use evaluator-provided tasks directly (no retention of stale tasks).
            state["task_list"] = tasks
            if args.verbose:
                vprint(
                    f"{prefix} EVALUATOR: parsed NEW_TASKS={len(tasks)} (after filtering)"
                )
        return state

    # GRAPH
    g = StateGraph(State)
    g.add_node("tasker", tasker_node)
    g.add_node("coder", coder_node)
    g.add_node("evaluator", evaluator_node)

    # Always proceed Tasker -> Coder; Evaluator alone can set done=True (PASS)
    g.add_edge("tasker", "coder")
    g.add_edge("coder", "evaluator")

    def _next_after_evaluator(state: State) -> str:
        return "end"

    g.add_conditional_edges(
        "evaluator",
        _next_after_evaluator,
        {
            "end": END,
        },
    )
    g.set_entry_point("tasker")
    app = g.compile()

    # PASS/FAIL parsing helpers
    def _parse_decision(md: str) -> str:
        lines = [ln.strip() for ln in (md or "").splitlines()]
        for i, ln in enumerate(lines):
            if ln.upper().startswith("DECISION"):
                # Same-line variant: "DECISION: PASS" / "DECISION: FAIL"
                if ":" in ln:
                    val = ln.split(":", 1)[1].strip().upper()
                    if val in {"PASS", "FAIL"}:
                        return val
                # Next non-empty line variant:
                j = i + 1
                while j < len(lines) and lines[j] == "":
                    j += 1
                if j < len(lines):
                    nxt = lines[j].upper()
                    if nxt in {"PASS", "FAIL"}:
                        return nxt
                break
        return "FAIL"

    def _pass_from_md(md: str) -> bool:
        return _parse_decision(md) == "PASS"

    # RUN LOOP
    logf = open(os.path.join(args.output, "log.jsonl"), "a", encoding="utf-8")
    statef = open(os.path.join(args.output, "state.jsonl"), "a", encoding="utf-8")
    prev_totals = {"input": 0, "output": 0}

    print(
        "Starting loop… (if this hangs, a network call is stuck; use --verbose and check CRASH_* files)"
    )
    for i in range(MAX_ITERS):
        vprint(f"==== Iteration {i+1}/{MAX_ITERS} ====")
        t0 = time.time()
        state["iter"] = i + 1
        state_local = cast(State, app.invoke(state))  # safe cast
        state.update(state_local)
        # Belt-and-suspenders: if evaluator reports PASS, force done=True
        try:
            if _pass_from_md(state.get("evaluator_md", "")):
                state["done"] = True
                # Write a marker file once for auditability
                marker = os.path.join(args.output, "PASS_MARKER")
                if not os.path.exists(marker):
                    pathlib.Path(marker).write_text(
                        "evaluator decision PASS\n", encoding="utf-8"
                    )
        except Exception:
            # Non-fatal; keep running with evaluator-set state
            pass
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

        logf.write(
            json.dumps(
                {
                    "iter": i + 1,
                    "mode": "multi",
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

        statef.write(json.dumps(state, ensure_ascii=False) + "\n")
        statef.flush()

        print(f"Iter {i+1} done. done={state['done']}, tasks={len(state['task_list'])}")
        if state["done"]:
            break

    logf.close()
    statef.close()

    # Final summary
    finalize_summary(args.output, pricing, pricing_missing, args.verbose)
