import json
import time
import os
import pathlib

from app.constants import INIT_CODE
from app.utils.io import vprint, safe_invoke, normalize_content, set_args
from app.utils.tokens import TOK, add_usage, extract_usage
from app.utils.pricing import load_pricing
from app.utils.summary import finalize_summary
from provider import make_llm


def run_single(args) -> None:
    """
    Single-agent programmer with human-in-the-loop interactive loop.
    Mirrors behavior from the previous run.py single mode.
    """
    # Make io utils aware of args for vprint/safe_invoke
    set_args(args)

    vprint(
        "CONFIG (single):",
        f"programmer_prompt={'(fallback to --coder)' if not args.programmer else args.programmer}",
        f"requirements={args.requirements}",
        f"output={args.output}",
    )

    # Programmer system prompt: prefer --programmer, else fallback to --coder if provided, else a minimal built-in.
    prog_path = args.programmer or args.coder
    if prog_path and pathlib.Path(prog_path).is_file():
        SYSTEM_PROG = pathlib.Path(prog_path).read_text(encoding="utf-8")
    else:
        SYSTEM_PROG = (
            "You are the Programmer (single agent). Implement the given Requirements immediately.\n\n"
            "When producing code: Output ONLY the full, updated index.html between <FILE> and </FILE>.\n"
            "Single file, client-only. No servers or external calls. Follow acceptance criteria exactly.\n"
            "Keep comments that map code to requirement sections where relevant.\n\n"
            "Chat: If the user asks something that does not require code changes, answer briefly as text.\n"
            "If code changes are needed, return ONLY the full index.html within <FILE> ... </FILE>.\n"
        )

    requirements_txt = pathlib.Path(args.requirements).read_text(encoding="utf-8")

    # Create a programmer LLM (supports OPENAI_PROGRAMMER_MODEL etc.; falls back to provider default)
    llm_prog = make_llm("programmer", temperature=0.0)

    pricing, pricing_missing = load_pricing()
    if args.verbose:
        if pricing_missing:
            vprint("PRICING:", pricing_missing)
        else:
            vprint(
                "PRICING (USD per 1M):",
                f"default in={pricing['default']['in']}, cached_in={pricing['default']['cached_in']}, out={pricing['default']['out']}",
                f"coder in={pricing['coder']['in']}, cached_in={pricing['coder']['cached_in']}, out={pricing['coder']['out']} (used for single mode)",
            )

    # Initialize log files
    logf = open(os.path.join(args.output, "log.jsonl"), "a", encoding="utf-8")
    statef = open(os.path.join(args.output, "state.jsonl"), "a", encoding="utf-8")
    prev_totals = {"input": 0, "output": 0}

    # Conversation messages
    messages = [
        {"role": "system", "content": SYSTEM_PROG},
        {
            "role": "user",
            "content": (
                "Requirements:\n" + requirements_txt + "\n\n"
                "Produce the full index.html within <FILE>...</FILE> and begin implementation now."
            ),
        },
    ]

    iter_no = 1
    code_html = INIT_CODE

    print("Starting single-agent HITL session…")
    t0 = time.time()
    resp = safe_invoke(llm_prog, messages, "PROGRAMMER", iter_no)
    it, ot, cit = extract_usage(resp)
    add_usage("coder", it, ot, cit)  # map to coder bucket for pricing
    text = normalize_content(resp.content)

    start = text.find("<FILE>")
    end = text.find("</FILE>")
    code = text[start + 6 : end] if start != -1 and end != -1 else text
    code_html = code

    # Save artifacts
    pathlib.Path(args.output, "index.html").write_text(code_html, encoding="utf-8")
    pathlib.Path(args.output, f"index_iter{iter_no}.html").write_text(
        code_html, encoding="utf-8"
    )

    # Log iteration
    dur = round(time.time() - t0, 2)
    delta_in = TOK["total"]["input"] - prev_totals["input"]
    delta_out = TOK["total"]["output"] - prev_totals["output"]
    prev_totals["input"] = TOK["total"]["input"]
    prev_totals["output"] = TOK["total"]["output"]

    logf.write(
        json.dumps(
            {
                "iter": iter_no,
                "mode": "single",
                "done": False,
                "task_list": [],  # not used in single mode
                "duration_s": dur,
                "tokens_iter": {"input": delta_in, "output": delta_out},
                "tokens_cumulative": {
                    "input": TOK["total"]["input"],
                    "output": TOK["total"]["output"],
                },
                "tokens_by_agent": TOK,
            },
            ensure_ascii=False,
        )
        + "\n"
    )
    logf.flush()

    # State snapshot
    state_snapshot = {
        "code_html": code_html,
        "task_list": [],
        "evaluator_md": "",
        "done": False,
        "iter": iter_no,
        "mode": "single",
    }
    statef.write(json.dumps(state_snapshot, ensure_ascii=False) + "\n")
    statef.flush()

    print(f"Initial implementation saved to {args.output}/index.html")
    print(
        "Commands: accept | status | help | cancel; or type instructions to the programmer to iterate."
    )

    # Interactive loop
    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting (no acceptance). Writing summary…")
            break

        if cmd.lower() in ("accept", "a"):
            # finalize
            break
        if cmd.lower() in ("cancel",):
            # Just exit; still write summary
            print("Cancelled by user. Writing summary…")
            break
        if cmd.lower() in ("status", "s"):
            print(
                f"iter={iter_no}, code chars={len(code_html)}, tokens(in={TOK['total']['input']}, out={TOK['total']['output']})"
            )
            continue
        if cmd.lower() in ("help", "h", "?"):
            print(
                "Commands: accept | status | help | cancel; or type instructions to the programmer to iterate."
            )
            continue

        # Treat any other input as user instruction
        messages.append({"role": "user", "content": cmd})
        iter_no += 1

        t0 = time.time()
        resp = safe_invoke(llm_prog, messages, "PROGRAMMER", iter_no)
        it, ot, cit = extract_usage(resp)
        add_usage("coder", it, ot, cit)
        text = normalize_content(resp.content)

        if "<FILE>" in text and "</FILE>" in text:
            start = text.find("<FILE>")
            end = text.find("</FILE>")
            new_code = text[start + 6 : end]
            pathlib.Path(args.output, "index.html").write_text(
                new_code, encoding="utf-8"
            )
            pathlib.Path(args.output, f"index_iter{iter_no}.html").write_text(
                new_code, encoding="utf-8"
            )
            code_html = new_code
            print(f"Updated artifact written: index_iter{iter_no}.html")
        else:
            # Just assistant prose; echo a preview
            preview = (text[:400] + "…") if len(text) > 400 else text
            print(preview)

        messages.append({"role": "assistant", "content": text})

        # Log this turn
        dur = round(time.time() - t0, 2)
        delta_in = TOK["total"]["input"] - prev_totals["input"]
        delta_out = TOK["total"]["output"] - prev_totals["output"]
        prev_totals["input"] = TOK["total"]["input"]
        prev_totals["output"] = TOK["total"]["output"]

        logf.write(
            json.dumps(
                {
                    "iter": iter_no,
                    "mode": "single",
                    "done": False,
                    "task_list": [],
                    "duration_s": dur,
                    "tokens_iter": {"input": delta_in, "output": delta_out},
                    "tokens_cumulative": {
                        "input": TOK["total"]["input"],
                        "output": TOK["total"]["output"],
                    },
                    "tokens_by_agent": TOK,
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        logf.flush()

        state_snapshot = {
            "code_html": code_html,
            "task_list": [],
            "evaluator_md": "",
            "done": False,
            "iter": iter_no,
            "mode": "single",
        }
        statef.write(json.dumps(state_snapshot, ensure_ascii=False) + "\n")
        statef.flush()

    # Close logs
    logf.close()
    statef.close()

    # Final summary
    finalize_summary(args.output, pricing, pricing_missing, args.verbose)
