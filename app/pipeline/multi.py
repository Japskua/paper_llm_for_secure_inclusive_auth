import json
import time
import os
import pathlib
from typing import List, TypedDict, cast

from langgraph.graph import StateGraph, END

from app.constants import INIT_CODE
from app.utils.io import vprint, safe_invoke, normalize_content, set_args
from app.utils.tokens import (
    MODEL_VERSIONS,
    MODELS_SEEN,
    TOK,
    add_usage,
    extract_usage,
    resolve_providers,
)
from app.utils.parsing import is_pass, parse_decision, parse_new_tasks, parse_task_list
from app.utils.pricing import load_pricing
from app.utils.summary import finalize_summary
from provider import make_three_llms, resolved_models


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

    # Protocol compliance counters. A model that cannot follow "output STRICT
    # JSON" is a result in its own right, so the corrective retry below is
    # recorded rather than silently absorbed.
    protocol = {
        "tasker_json_parse_failures": 0,
        "tasker_json_recovered_by_retry": 0,
        "tasker_json_hard_failures": 0,
    }

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
        messages = [
            {"role": "system", "content": SYSTEM_TASKER},
            {"role": "user", "content": user_msg},
        ]

        # Models vary in whether they honour "STRICT JSON": some wrap the object
        # in ``` fences or add a preamble. parse_task_list tolerates both; if it
        # still fails we re-ask once with a corrective instruction rather than
        # killing a run that may already be hours old.
        new_list = None
        text = ""
        for attempt in (1, 2):
            resp = safe_invoke(llm_tasker, messages, "TASKER", int(state.get("iter", 0)))
            usage = extract_usage(resp)
            add_usage("tasker", usage)
            if args.verbose:
                vprint(
                    f"{prefix} TASKER tokens: input={usage['input']}, "
                    f"cached_input={usage['cached_input']}, output={usage['output']}, "
                    f"reasoning={usage['reasoning']}"
                )

            text = normalize_content(resp.content)
            if args.verbose:
                preview = (text[:400] + "…") if len(text) > 400 else text
                vprint(f"{prefix} TASKER output (preview): {preview}")

            try:
                new_list = parse_task_list(text)
                if attempt == 2:
                    protocol["tasker_json_recovered_by_retry"] += 1
                break
            except ValueError:
                protocol["tasker_json_parse_failures"] += 1
                if attempt == 2:
                    protocol["tasker_json_hard_failures"] += 1
                    vprint(f"{prefix} TASKER JSON ERROR after retry. Raw:\n{text}")
                    pathlib.Path(
                        args.output, f"PROTOCOL_VIOLATION_tasker_json_iter{state.get('iter', 0)}.txt"
                    ).write_text(text, encoding="utf-8")
                    raise ValueError(
                        f"Tasker did not return valid JSON after 2 attempts. Got:\n{text}"
                    )
                vprint(f"{prefix} TASKER: unparseable JSON, re-asking once")
                messages = messages + [
                    {"role": "assistant", "content": text},
                    {
                        "role": "user",
                        "content": (
                            "That was not valid JSON. Reply with ONLY a JSON object "
                            'of the form {"task_list": ["...", "..."]} — no prose, '
                            "no markdown code fences."
                        ),
                    },
                ]

        assert new_list is not None
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
        # Always overwrite: a re-run of this run directory must not inherit
        # artifacts from a previous attempt.
        versioned_path.write_text(report_md, encoding="utf-8")
        if args.verbose:
            vprint(f"{prefix} TASKER: wrote tasker_report.md and {versioned_path.name}")

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
        usage = extract_usage(resp)
        add_usage("coder", usage)
        if args.verbose:
            vprint(
                f"{prefix} CODER tokens: input={usage['input']}, "
                f"cached_input={usage['cached_input']}, output={usage['output']}, "
                f"reasoning={usage['reasoning']}"
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
        usage = extract_usage(resp)
        add_usage("evaluator", usage)
        if args.verbose:
            vprint(
                f"{prefix} EVALUATOR tokens: input={usage['input']}, "
                f"cached_input={usage['cached_input']}, output={usage['output']}, "
                f"reasoning={usage['reasoning']}"
            )

        text = normalize_content(resp.content)
        state["evaluator_md"] = text

        pathlib.Path(args.output, "evaluator_report.md").write_text(
            text, encoding="utf-8"
        )
        iter_no = int(state.get("iter", 0))
        versioned_name = f"evaluator_report_iter{iter_no}.md"
        pathlib.Path(args.output, versioned_name).write_text(text, encoding="utf-8")

        decision = parse_decision(text)

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
            # Use evaluator-provided tasks directly (no retention of stale tasks).
            tasks = parse_new_tasks(text)
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

    # RUN LOOP
    # Write mode, not append: one run per directory. Appending across attempts
    # made per-iteration token deltas meaningless (prev_totals restarts at 0).
    logf = open(os.path.join(args.output, "log.jsonl"), "w", encoding="utf-8")
    statef = open(os.path.join(args.output, "state.jsonl"), "w", encoding="utf-8")
    prev_totals = {"input": 0, "output": 0}
    converged = False

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
            if is_pass(state.get("evaluator_md", "")):
                state["done"] = True
                # Marker file for auditability; rewritten each attempt.
                pathlib.Path(args.output, "PASS_MARKER").write_text(
                    f"evaluator decision PASS at iteration {i + 1}\n", encoding="utf-8"
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
                        "reasoning": TOK["total"]["reasoning"],
                        "cost_usd": TOK["total"]["cost_usd"],
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
            converged = True
            break

    logf.close()
    statef.close()

    if not converged:
        # A run that exhausts max-iters is a recorded outcome, not a failure to
        # hide: convergence rate is itself reportable per case.
        pathlib.Path(args.output, "NO_CONVERGENCE").write_text(
            f"evaluator never returned PASS within {MAX_ITERS} iterations\n",
            encoding="utf-8",
        )
        print(f"WARNING: no convergence within {MAX_ITERS} iterations.")

    # Final summary
    finalize_summary(
        args.output,
        pricing,
        pricing_missing,
        args.verbose,
        run_meta={
            "converged": converged,
            "iterations": int(state.get("iter", 0)),
            "max_iters": MAX_ITERS,
            "protocol_violations": protocol,
            "models": resolved_models(),
            "models_served": dict(MODELS_SEEN),
            # resolve_providers() also populates MODEL_VERSIONS, so it must run first.
            "providers_seen": resolve_providers(),
            "model_versions": dict(MODEL_VERSIONS),
            "requirements": args.requirements,
        },
    )
