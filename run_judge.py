#!/usr/bin/env python
"""
Judging stage (Phase 2, step 2).

Every artifact is scored by every judge on both tracks, repeated N times:

    30 artifacts x 2 tracks x 7 judges x 3 repeats = 1260 judgements

Each judgement is written to a path that encodes its identity, so two records
can never collide:

    final_evaluations/results_v2/<track>/<case>/<run>/<judge>/repeat_N.json

Every record embeds the SHA-256 of both the rubric used and the artifact scored,
and the artifact hash is checked against batch_manifest.json before any call is
made — an artifact that does not match the manifest is refused rather than
silently scored.

Three analysis-ready tables are written at the end:

    scores_long.csv      one row per item score (the tidy primary table)
    scores_artifact.csv  one row per judgement, with construct means
    summary_case.csv     case x track means, the paper table

Example:
    uv run python run_judge.py --repeats 3 --concurrency 6
"""

import argparse
import csv
import json
import pathlib
import threading
import time
from concurrent import futures
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

REPO = pathlib.Path(__file__).resolve().parent
RUBRICS = REPO / "final_evaluations" / "evaluation_rubrics"
RESULTS = REPO / "final_evaluations" / "results_v2"

# Reentrant by necessity: work() holds this while updating counters and then
# calls log(), which acquires it again. With a plain Lock that is a self
# deadlock — every run stopped dead on its 25th completion, with the remaining
# workers blocking behind the stuck one.
_print_lock = threading.RLock()


def log(msg: str) -> None:
    with _print_lock:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def slug(model: str) -> str:
    return model.replace("/", "__").replace(".", "-")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--software", default="password_recovery_health")
    p.add_argument("--output-root", default="generations")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--concurrency", type=int, default=6)
    p.add_argument("--tracks", nargs="*", default=["security", "inclusivity"])
    p.add_argument("--judges", nargs="*", help="Override the panel from judge_panel.json")
    p.add_argument("--cases", nargs="*")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--force", action="store_true", help="Re-judge existing records")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--tables-only", action="store_true",
                   help="Rebuild the CSV tables from existing records, no API calls")
    return p.parse_args()


def load_panel(args) -> List[str]:
    if args.judges:
        return args.judges
    cfg = json.loads((REPO / "final_evaluations" / "judge_panel.json").read_text())
    return [j["id"] for j in cfg["panel"]]


def load_artifacts(args) -> List[Dict[str, Any]]:
    root = REPO / args.output_root / args.software
    manifest = json.loads((root / "batch_manifest.json").read_text())
    capture = {}
    cap_path = root / "capture_summary.json"
    if cap_path.is_file():
        capture = {r["run_id"]: r for r in json.loads(cap_path.read_text())["runs"]}

    out = []
    for r in manifest["runs"]:
        if args.cases and r["case"] not in args.cases:
            continue
        if r["run_index"] > args.runs:
            continue
        run_dir = REPO / r["output_dir"]
        if not (run_dir / "app.ts").is_file():
            continue
        cap = capture.get(r["run_id"], {})
        out.append({
            "run_dir": run_dir,
            "case": r["case"],
            "run": run_dir.name,
            "artifact_id": r["run_id"],
            "app_ts_sha256": r.get("app_ts_sha256"),
            "capture_complete": bool(cap.get("ok")),
            "screenshot_count": len(cap.get("screenshots") or []),
        })
    return out


def record_path(track: str, case: str, run: str, judge: str, repeat: int) -> pathlib.Path:
    return RESULTS / track / case / run / slug(judge) / f"repeat_{repeat}.json"


def write_record(path: pathlib.Path, record: Dict[str, Any]) -> None:
    """
    Write atomically. A process killed midway through a plain write leaves a
    truncated file that still exists, which resume would treat as done and the
    table builder would silently drop.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def is_done(path: pathlib.Path) -> bool:
    """
    A judgement counts as done only if it is a readable success, or a permanent
    and legitimate skip (an artifact with no screenshots can never be scored on
    the inclusivity track). Transient failures and truncated files are redone,
    so a crashed or rate-limited run does not bake its errors into the dataset.
    """
    if not path.is_file():
        return False
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if record.get("ok"):
        return True
    return record.get("reason") == "no_screenshots"


def build_tables(args) -> Dict[str, int]:
    """Collect every record on disk into three analysis-ready CSVs."""
    from app.utils.judge import CONSTRUCTS, REVERSE_CODED

    item_construct = {
        track: {i: name for name, items in groups.items() for i in items}
        for track, groups in CONSTRUCTS.items()
    }

    long_rows, artifact_rows = [], []
    for rec_file in sorted(RESULTS.rglob("repeat_*.json")):
        try:
            r = json.loads(rec_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not r.get("ok"):
            continue
        track = r["track"]
        for item in range(1, 16):
            entry = r["scores"][str(item)]
            long_rows.append({
                "artifact_id": r["artifact_id"], "case": r["case"], "run": r["run"],
                "track": track, "judge": r["judge"], "repeat": r["repeat"],
                "item": item, "construct": item_construct[track][item],
                "raw_score": entry["score"],
                "adjusted_score": r["adjusted_scores"][str(item)]
                if isinstance(r["adjusted_scores"], dict) and str(item) in r["adjusted_scores"]
                else r["adjusted_scores"][item] if isinstance(r["adjusted_scores"], dict)
                else None,
                "reverse_coded": item in REVERSE_CODED[track],
                "screenshot_count": r.get("screenshot_count", 0),
                "justification": (entry.get("why") or "").replace("\n", " "),
            })
        row = {
            "artifact_id": r["artifact_id"], "case": r["case"], "run": r["run"],
            "track": track, "judge": r["judge"], "repeat": r["repeat"],
            "overall": r["overall"], "rubric_file": r["rubric_file"],
            "rubric_sha256": r["rubric_sha256"][:12],
            "app_ts_sha256": (r.get("app_ts_sha256") or "")[:12],
            "screenshot_count": r.get("screenshot_count", 0),
            "screenshots_available": r.get("screenshots_available", 0),
            "screenshots_sampled": bool(r.get("screenshots_sampled")),
        }
        row.update({f"c_{k}": v for k, v in r["constructs"].items()})
        artifact_rows.append(row)

    RESULTS.mkdir(parents=True, exist_ok=True)

    def write(name: str, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        keys, seen = [], set()
        for row in rows:
            for k in row:
                if k not in seen:
                    seen.add(k); keys.append(k)
        with open(RESULTS / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)

    write("scores_long.csv", long_rows)
    write("scores_artifact.csv", artifact_rows)

    # case x track summary
    agg: Dict[Any, List[float]] = {}
    for row in artifact_rows:
        agg.setdefault((row["case"], row["track"]), []).append(row["overall"])
    summary = []
    for (case, track), vals in sorted(agg.items()):
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1) if len(vals) > 1 else 0.0
        summary.append({
            "case": case, "track": track, "judgements": len(vals),
            "mean_overall": round(mean, 4), "sd_overall": round(var ** 0.5, 4),
            "min": round(min(vals), 4), "max": round(max(vals), 4),
        })
    write("summary_case.csv", summary)
    return {"long_rows": len(long_rows), "judgements": len(artifact_rows),
            "summary_rows": len(summary)}


def main() -> int:
    args = parse_args()
    load_dotenv(override=True)

    if args.tables_only:
        counts = build_tables(args)
        log(f"tables rebuilt: {counts}")
        return 0

    import os
    from langchain_openai import ChatOpenAI
    from app.utils.judge import judge_artifact

    panel = load_panel(args)
    artifacts = load_artifacts(args)
    jobs = [
        (a, track, judge, rep)
        for a in artifacts
        for track in args.tracks
        for judge in panel
        for rep in range(1, args.repeats + 1)
    ]
    log(f"{len(artifacts)} artifacts x {len(args.tracks)} tracks x {len(panel)} judges "
        f"x {args.repeats} repeats = {len(jobs)} judgements")

    todo = [j for j in jobs
            if args.force or not is_done(record_path(j[1], j[0]["case"], j[0]["run"], j[2], j[3]))]
    retries = sum(
        1 for j in todo
        if record_path(j[1], j[0]["case"], j[0]["run"], j[2], j[3]).is_file()
    )
    log(f"{len(todo)} to run ({retries} of them retries of earlier failures), "
        f"{len(jobs) - len(todo)} already complete")

    if args.dry_run:
        for a, track, judge, rep in todo[:10]:
            print("  ", record_path(track, a["case"], a["run"], judge, rep).relative_to(REPO))
        if len(todo) > 10:
            print(f"   ... and {len(todo) - 10} more")
        return 0

    key = os.getenv("OPENROUTER_API_KEY")
    llms = {
        m: ChatOpenAI(model=m, api_key=key, base_url="https://openrouter.ai/api/v1",
                      timeout=600, max_retries=2, extra_body={"usage": {"include": True}})
        for m in panel
    }

    done = {"ok": 0, "failed": 0, "skipped": 0, "cost": 0.0}
    started = time.time()

    def work(job) -> None:
        a, track, judge, rep = job
        out = record_path(track, a["case"], a["run"], judge, rep)
        if track == "inclusivity" and a["screenshot_count"] == 0:
            write_record(out, {
                "ok": False, "reason": "no_screenshots", "artifact_id": a["artifact_id"],
                "case": a["case"], "run": a["run"], "track": track,
                "judge": judge, "repeat": rep,
            })
            with _print_lock:
                done["skipped"] += 1
            return
        try:
            rec = judge_artifact(
                a["run_dir"], track, a["case"], a["run"], judge, rep,
                llms[judge], RUBRICS, expected_app_sha=a["app_ts_sha256"],
            )
        except Exception as e:
            rec = {"ok": False, "reason": "exception", "error": f"{type(e).__name__}: {e}",
                   "artifact_id": a["artifact_id"], "case": a["case"], "run": a["run"],
                   "track": track, "judge": judge, "repeat": rep}
        rec["capture_complete"] = a["capture_complete"]
        write_record(out, rec)
        with _print_lock:
            if rec.get("ok"):
                done["ok"] += 1
                done["cost"] += float(rec.get("cost_usd") or 0.0)
            else:
                done["failed"] += 1
                log(f"  FAIL {a['artifact_id']} {track} {judge} r{rep}: "
                    f"{rec.get('reason')} {str(rec.get('error'))[:70]}")
            total = done["ok"] + done["failed"] + done["skipped"]
            if total % 25 == 0:
                log(f"  {total}/{len(todo)} done | ok={done['ok']} failed={done['failed']} "
                    f"skipped={done['skipped']} | ${done['cost']:.2f} | "
                    f"{(time.time() - started) / 60:.1f} min")

    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        list(pool.map(work, todo))

    counts = build_tables(args)
    log("=" * 72)
    log(f"ok {done['ok']} | failed {done['failed']} | skipped {done['skipped']} "
        f"| ${done['cost']:.2f} | {(time.time() - started) / 60:.1f} min")
    log(f"tables: {counts['judgements']} judgements, {counts['long_rows']} item rows")
    log(f"  -> {(RESULTS / 'scores_long.csv').relative_to(REPO)}")
    log(f"  -> {(RESULTS / 'scores_artifact.csv').relative_to(REPO)}")
    log(f"  -> {(RESULTS / 'summary_case.csv').relative_to(REPO)}")
    return 0 if done["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
