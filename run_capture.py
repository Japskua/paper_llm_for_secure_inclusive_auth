#!/usr/bin/env python
"""
Screenshot capture stage (Phase 2, step 1).

Walks every generated artifact through its recovery journey in Chromium and
photographs each step, producing the images the inclusivity rubric is scored
from. Screenshots are written inside the run directory so everything about a run
stays together:

    generations/<software>/<case>/run_NN/screenshots/step_NN_<name>.png
    generations/<software>/<case>/run_NN/capture.json     result
    generations/<software>/<case>/run_NN/ui_script.json   derived walkthrough

Capture is serialised, not parallel: artifacts bind fixed ports (443, 80 and
3000 have all been observed), so only one may run at a time. The per-artifact
walkthrough is model-derived because every run invents its own interface — see
app/utils/capture.py.

Artifacts that stall part-way keep the screenshots taken up to that point and
are recorded as partial rather than dropped, so a broken journey remains visible
in the data instead of silently disappearing.

Example:
    uv run python run_capture.py --runs 10
"""

import argparse
import json
import pathlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from dotenv import load_dotenv

REPO = pathlib.Path(__file__).resolve().parent


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--software", default="password_recovery_health")
    p.add_argument("--output-root", default="generations")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--run-start", type=int, default=1)
    p.add_argument("--cases", nargs="*")
    p.add_argument("--certs", default="workspace/certs")
    p.add_argument(
        "--model",
        default=None,
        help="Model used to derive each walkthrough (default: the evaluator model from .env)",
    )
    p.add_argument("--force", action="store_true", help="Recapture runs already done")
    p.add_argument(
        "--rederive",
        action="store_true",
        help="Discard the cached ui_script.json and derive the walkthrough afresh",
    )
    p.add_argument("--no-repair", dest="repair", action="store_false", default=True)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def discover(args) -> List[pathlib.Path]:
    root = REPO / args.output_root / args.software
    if not root.is_dir():
        raise SystemExit(f"No such directory: {root}")
    cases = args.cases or sorted(d.name for d in root.iterdir() if d.is_dir())
    runs = []
    for case in cases:
        for i in range(args.run_start, args.run_start + args.runs):
            d = root / case / f"run_{i:02d}"
            if (d / "app.ts").is_file():
                runs.append(d)
    return runs


def already_done(run: pathlib.Path) -> bool:
    result = run / "capture.json"
    if not result.is_file():
        return False
    try:
        return bool(json.loads(result.read_text(encoding="utf-8")).get("ok"))
    except Exception:
        return False


def main() -> int:
    args = parse_args()
    load_dotenv(override=True)

    runs = discover(args)
    log(f"{len(runs)} artifacts found")

    if args.dry_run:
        for r in runs:
            state = "captured" if already_done(r) else "pending"
            print(f"  {r.relative_to(REPO)}  {state}")
        return 0

    from app.utils.capture import capture
    from provider import make_llm

    import os

    if args.model:
        os.environ["OPENROUTER_MODEL"] = args.model
    llm = make_llm("evaluator")

    records: List[Dict[str, Any]] = []
    started = time.time()

    for run in runs:
        rel = run.relative_to(REPO)
        run_id = f"{run.parent.name}/{run.name}"

        if already_done(run) and not args.force:
            record = json.loads((run / "capture.json").read_text(encoding="utf-8"))
            record["run_id"] = run_id
            record["reused"] = True
            records.append(record)
            log(f"SKIP  {run_id} ({record.get('steps_captured')} shots, already captured)")
            continue

        t0 = time.time()
        try:
            result = capture(
                str(run),
                llm,
                out_dir=str(run / "screenshots"),
                certs_src=args.certs,
                reuse_spec=not args.rederive,
                repair=args.repair,
            )
        except Exception as e:
            result = {
                "ok": False,
                "stage": "exception",
                "error": f"{type(e).__name__}: {e}",
                "screenshots": [],
            }
        result["run_id"] = run_id
        result["seconds"] = round(time.time() - t0, 1)
        records.append(result)

        verdict = "OK  " if result.get("ok") else "PART" if result.get("screenshots") else "FAIL"
        log(
            f"{verdict}  {run_id} {result.get('stage'):<22}"
            f"shots={result.get('steps_captured', 0)}/{result.get('steps_planned', 0)} "
            f"via={result.get('chosen_attempt')} {result['seconds']}s"
        )
        if not result.get("ok") and result.get("failure"):
            log(f"        stalled at '{result['failure'].get('step')}': "
                f"{str(result['failure'].get('error'))[:100]}")
        elif not result.get("ok"):
            log(f"        {str(result.get('error'))[:110]}")

    complete = [r for r in records if r.get("ok")]
    partial = [r for r in records if not r.get("ok") and r.get("screenshots")]
    failed = [r for r in records if not r.get("ok") and not r.get("screenshots")]

    by_case: Dict[str, Dict[str, int]] = {}
    for r in records:
        case = r["run_id"].split("/")[0]
        c = by_case.setdefault(case, {"complete": 0, "partial": 0, "failed": 0, "shots": 0})
        c["complete" if r.get("ok") else ("partial" if r.get("screenshots") else "failed")] += 1
        c["shots"] += len(r.get("screenshots") or [])

    summary = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "software": args.software,
        "artifacts": len(records),
        "complete": len(complete),
        "partial": len(partial),
        "failed": len(failed),
        "total_screenshots": sum(len(r.get("screenshots") or []) for r in records),
        "wall_seconds": round(time.time() - started, 1),
        "by_case": by_case,
        "runs": records,
    }
    out = REPO / args.output_root / args.software / "capture_summary.json"
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    log("=" * 72)
    log(f"complete {len(complete)}/{len(records)} | partial {len(partial)} | failed {len(failed)}")
    log(f"{summary['total_screenshots']} screenshots | wall {summary['wall_seconds'] / 60:.1f} min")
    for case, c in by_case.items():
        log(f"  {case[:44]:<46} complete={c['complete']} partial={c['partial']} failed={c['failed']} shots={c['shots']}")
    log(f"summary -> {out.relative_to(REPO)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
