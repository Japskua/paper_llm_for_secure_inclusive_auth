#!/usr/bin/env python
"""
Batch runner for the repeated-generation experiment (Phase 1).

Runs N independent generations per case and writes a manifest describing every
artifact produced. Each run executes in its own subprocess, which:

  * isolates the module-level counters in app/utils/tokens.py, so one run's
    token totals can never leak into another's, and
  * contains crashes, so a failed run cannot take the batch down.

Runs are independent draws: no seed is set anywhere. On models that expose
temperature it can be pinned with --temperature; frontier reasoning models
(GPT-5.x, Sonnet 5) sample at a fixed internal temperature instead, which is
recorded per run in the manifest.

Example:
    uv run python run_batch.py --runs 10 --concurrency 6 \
        --model openai/gpt-5.6-terra --reasoning-effort medium \
        --max-iters 12 --smoke-test
"""

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

REPO = pathlib.Path(__file__).resolve().parent

# case key -> requirements file, relative to requirements/<software>/
SOFTWARE = {
    "password_recovery_health": {
        "case_1_multi_no_condition_no_inclusion": "password_recovery_health_no_inclusivity_no_condition.md",
        "case_2_multi_condition_no_inclusion": "password_recovery_health_no_inclusivity.md",
        "case_3_multi_condition_with_inclusion": "password_recovery_health_with_inclusivity.md",
    }
}

_print_lock = threading.Lock()
# Set when a credentials/model-id fault is seen, so the batch stops instead of
# recording dozens of failures that say nothing about the model.
_abort = threading.Event()


def log(msg: str) -> None:
    with _print_lock:
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] {msg}", flush=True)


def sha256_file(path: pathlib.Path) -> Optional[str]:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def read_json(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--software", default="password_recovery_health", choices=sorted(SOFTWARE))
    p.add_argument(
        "--output-root",
        default="generations",
        help=(
            "Root directory for generated artifacts (default: generations). "
            "The original single-run dataset lives under workspace/."
        ),
    )
    p.add_argument(
        "--legacy-root",
        default="workspace",
        help="Root holding the previously published artifacts, for --archive-legacy.",
    )
    p.add_argument("--runs", type=int, default=10, help="Independent runs per case (default: 10)")
    p.add_argument("--run-start", type=int, default=1, help="First run index (default: 1)")
    p.add_argument("--cases", nargs="*", help="Subset of case keys to run (default: all)")
    p.add_argument("--concurrency", type=int, default=6, help="Runs in flight (default: 6)")
    p.add_argument("--max-iters", type=int, default=12)
    p.add_argument("--model", default=os.getenv("OPENROUTER_MODEL", "openai/gpt-5.6-terra"))
    p.add_argument("--reasoning-effort", choices=["minimal", "low", "medium", "high"], default="medium")
    p.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="Only applied if the model exposes it; ignored otherwise (recorded in the manifest).",
    )
    p.add_argument("--retries", type=int, default=2, help="Retries per failed run (default: 2)")
    p.add_argument("--smoke-test", action="store_true", default=True)
    p.add_argument("--no-smoke-test", dest="smoke_test", action="store_false")
    p.add_argument(
        "--flow-test",
        action="store_true",
        help="Also walk the full recovery journey against each artifact (see app/utils/flow.py)",
    )
    p.add_argument("--certs", default="workspace/certs")
    p.add_argument("--force", action="store_true", help="Re-run runs that already completed")
    p.add_argument(
        "--reverify",
        action="store_true",
        help=(
            "Re-run smoke/flow verification on already-complete runs without "
            "regenerating them. Use after fixing a harness defect so stale "
            "verdicts are corrected in place."
        ),
    )
    p.add_argument("--dry-run", action="store_true", help="List planned runs and exit")
    p.add_argument("--verbose", action="store_true", default=True)
    p.add_argument("--quiet", dest="verbose", action="store_false")
    p.add_argument(
        "--archive-legacy",
        action="store_true",
        help="Move pre-existing top-level case artifacts into legacy_gpt4o/ before running",
    )
    return p.parse_args()


def plan_runs(args) -> List[Dict[str, Any]]:
    cases = args.cases or list(SOFTWARE[args.software])
    unknown = [c for c in cases if c not in SOFTWARE[args.software]]
    if unknown:
        raise SystemExit(f"Unknown case(s): {', '.join(unknown)}")

    planned = []
    for case in cases:
        req = REPO / "requirements" / args.software / SOFTWARE[args.software][case]
        if not req.is_file():
            raise SystemExit(f"Requirements file not found: {req}")
        for i in range(args.run_start, args.run_start + args.runs):
            out = REPO / args.output_root / args.software / case / f"run_{i:02d}"
            planned.append(
                {
                    "run_id": f"{case}/run_{i:02d}",
                    "case": case,
                    "run_index": i,
                    "requirements": str(req.relative_to(REPO)),
                    "requirements_sha256": sha256_file(req),
                    "output_dir": str(out.relative_to(REPO)),
                    "_out": out,
                    "_req": req,
                }
            )
    return planned


def is_complete(out: pathlib.Path) -> bool:
    """A run is complete when it wrote a summary and reached a terminal verdict."""
    return (out / "tokens_summary.json").is_file() and (
        (out / "PASS_MARKER").is_file() or (out / "NO_CONVERGENCE").is_file()
    )


# Signatures that identify a failure as infrastructure rather than the model's
# doing. Only these are retried: a model or pipeline failure is a result and
# must be recorded, not replaced by a fresh attempt.
_INFRA_SIGNS = (
    "readtimeout",
    "connecttimeout",
    "connecterror",
    "connectionerror",
    "remoteprotocolerror",
    "ratelimit",
    "rate_limit",
    "http 429",
    "http 500",
    "http 502",
    "http 503",
    "http 504",
    "http 529",
    "apiconnectionerror",
    "internalservererror",
    "overloaded",
    "retries exhausted",
    "temporarily unavailable",
)

_MODEL_SIGNS = (
    "did not return valid json",
    "protocol_violation",
    "tasker did not return",
)

# Credentials or model-id problems. These are not results: they would otherwise
# fill the dataset with failures that say nothing about the model, so they abort
# the batch immediately instead.
_CONFIG_SIGNS = (
    "authenticationerror",
    "error code: 401",
    "error code: 403",
    "invalid api key",
    "no auth credentials",
    "user not found",
    "is not a valid model id",
    "no endpoints found",
    "notfounderror",
)


def classify_failure(out: pathlib.Path) -> Dict[str, Any]:
    """
    Decide whether a failed run died from infrastructure or from the model.

    Defaults to "unknown", which is NOT retried: only a positively identified
    infrastructure fault may be absorbed by a retry. Anything else stays in the
    dataset as a recorded failure, because non-working output is a result.
    """
    evidence = []
    for crash in sorted(out.glob("CRASH_*.txt")):
        evidence.append(crash.read_text(encoding="utf-8", errors="replace")[:2000])
    console = out / "console.log"
    if console.is_file():
        evidence.append(console.read_text(encoding="utf-8", errors="replace")[-4000:])
    blob = "\n".join(evidence).lower()

    if any(sign in blob for sign in _CONFIG_SIGNS):
        kind = "configuration"
    elif any(sign in blob for sign in _MODEL_SIGNS):
        kind = "model"
    elif any(sign in blob for sign in _INFRA_SIGNS):
        kind = "infrastructure"
    else:
        kind = "unknown"

    detail = ""
    for line in reversed(blob.splitlines()):
        if any(t in line for t in ("error", "fatal", "exception", "traceback")):
            detail = line.strip()[:200]
            break
    return {"kind": kind, "detail": detail, "retryable": kind == "infrastructure"}


def archive_legacy(args) -> None:
    """
    Move the previously published single-run artifacts into a legacy/ subfolder,
    so the earlier GPT-4o dataset stays available but is clearly separated from
    the repeated-runs batch.
    """
    moved_any = False
    for case in SOFTWARE[args.software]:
        case_dir = REPO / args.legacy_root / args.software / case
        if not case_dir.is_dir():
            continue
        loose = [p for p in case_dir.iterdir() if p.is_file()]
        if not loose:
            log(f"archive: {case} already archived, nothing to move")
            continue
        dest = case_dir / "legacy_single_run_gpt4o"
        dest.mkdir(exist_ok=True)
        for p in loose:
            shutil.move(str(p), str(dest / p.name))
        log(f"archived {len(loose)} files -> {dest.relative_to(REPO)}")
        moved_any = True
    if not moved_any:
        log("archive: nothing to do")


def reverify(out: pathlib.Path, args) -> None:
    """
    Re-run verification against an existing artifact, leaving the generated code
    untouched. Needed because a harness defect can leave a correct artifact
    marked broken, and regenerating would replace the very sample under review.
    """
    from app.utils.smoke import smoke_test

    if args.smoke_test:
        smoke_test(str(out), certs_src=args.certs)
    if args.flow_test:
        from app.utils.flow import flow_test
        from provider import make_llm

        # reuse_spec=False: a stale plan may itself be the reason a run failed.
        flow_test(str(out), make_llm("evaluator"), certs_src=args.certs, reuse_spec=False)


def execute(job: Dict[str, Any], args) -> Dict[str, Any]:
    out: pathlib.Path = job["_out"]
    record = {k: v for k, v in job.items() if not k.startswith("_")}

    if _abort.is_set():
        record.update(status="aborted", reason="batch aborted by a configuration fault")
        return record

    if is_complete(out) and not args.force:
        if args.reverify:
            reverify(out, args)
        # Still collect: a resumed batch must produce a complete manifest, not
        # one where previously-finished runs appear as empty records.
        record.update(collect(out, exit_code=0, attempts=0, wall=0.0))
        record["reused"] = True
        record.setdefault("failed_attempts", [])
        record.setdefault("failure_cause", None)
        # protocol_violations stays None for runs generated before it was
        # recorded — absent is not the same as zero violations.
        log(f"SKIP  {job['run_id']} (already complete, results collected)")
        return record

    cmd = [
        sys.executable, "run.py",
        "--mode", "multi",
        "--tasker", "prompts/prompt_tasker.txt",
        "--coder", "prompts/prompt_coder.txt",
        "--eval", "prompts/prompt_evaluator.txt",
        "--requirements", job["requirements"],
        "--output", job["output_dir"],
        "--max-iters", str(args.max_iters),
        "--model", args.model,
        "--reasoning-effort", args.reasoning_effort,
    ]
    if args.temperature is not None:
        cmd += ["--temperature", str(args.temperature)]
    if args.smoke_test:
        cmd += ["--smoke-test", "--certs", args.certs]
    if args.flow_test:
        cmd += ["--flow-test", "--certs", args.certs]
    if args.verbose:
        cmd += ["--verbose"]

    attempts = 0
    exit_code = None
    started = time.time()
    failures: List[Dict[str, Any]] = []

    while attempts <= args.retries:
        attempts += 1
        if out.exists():
            # Preserve a failed attempt from THIS batch instead of deleting it:
            # a failed run is evidence, and erasing it would quietly convert a
            # failure into a success in the dataset. On the first attempt any
            # existing directory is a previous run being deliberately replaced
            # (--force), not a failure, so it is removed rather than archived.
            if attempts > 1 and any(out.iterdir()):
                # shutil.move() into an existing directory nests inside it
                # rather than replacing, so clear any stale attempt first.
                dest = out.parent / f"{out.name}_failed_attempt_{attempts - 1}"
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.move(str(out), str(dest))
            else:
                shutil.rmtree(out)
        out.mkdir(parents=True, exist_ok=True)

        log(f"START {job['run_id']} (attempt {attempts}/{args.retries + 1})")
        with open(out / "console.log", "w", encoding="utf-8") as console:
            proc = subprocess.run(cmd, cwd=str(REPO), stdout=console, stderr=subprocess.STDOUT)
        exit_code = proc.returncode

        if exit_code == 0:
            break

        cause = classify_failure(out)
        failures.append({"attempt": attempts, "exit_code": exit_code, **cause})

        if cause["kind"] == "configuration":
            _abort.set()
            log(
                f"ABORT {job['run_id']} exit={exit_code} cause=configuration — "
                f"stopping the batch: {cause['detail'][:120]}"
            )
            break

        if not cause["retryable"]:
            # Model or unknown cause: keep it as a recorded failure.
            log(
                f"FAIL  {job['run_id']} exit={exit_code} cause={cause['kind']} "
                f"— not retrying (recorded as a result)"
            )
            break
        if attempts > args.retries:
            log(f"FAIL  {job['run_id']} exit={exit_code} cause=infrastructure — retries exhausted")
            break
        log(f"FAIL  {job['run_id']} exit={exit_code} cause=infrastructure — retrying")

    record.update(collect(out, exit_code, attempts, round(time.time() - started, 2)))
    record["failed_attempts"] = failures
    record["failure_cause"] = failures[-1]["kind"] if failures and exit_code != 0 else None
    verdict = "OK" if record["status"] == "completed" else record["status"].upper()
    log(
        f"DONE  {job['run_id']} {verdict} iters={record.get('iterations')} "
        f"converged={record.get('converged')} smoke={(record.get('smoke') or {}).get('ok')} "
        f"flow={(record.get('flow') or {}).get('ok')} "
        f"cost=${record.get('cost_usd') or 0:.4f} {record['wall_seconds']}s"
    )
    return record


def collect(out: pathlib.Path, exit_code: Optional[int], attempts: int, wall: float) -> Dict[str, Any]:
    """Gather everything Phase 2 needs from a finished run directory."""
    summary = read_json(out / "tokens_summary.json") or {}
    smoke = read_json(out / "smoke.json") or {}
    flow = read_json(out / "flow.json") or {}
    run_meta = summary.get("run", {})
    totals = (summary.get("by_agent") or {}).get("total", {})
    app_ts = out / "app.ts"

    rec: Dict[str, Any] = {
        "status": "completed" if exit_code == 0 and summary else "failed",
        "exit_code": exit_code,
        "attempts": attempts,
        "wall_seconds": wall,
        "converged": run_meta.get("converged"),
        "iterations": run_meta.get("iterations"),
        "max_iters": run_meta.get("max_iters"),
        "models": run_meta.get("models"),
        "protocol_violations": run_meta.get("protocol_violations"),
        "models_served": run_meta.get("models_served"),
        "model_versions": run_meta.get("model_versions"),
        "providers_seen": run_meta.get("providers_seen"),
        "tokens": {
            "input": totals.get("input"),
            "output": totals.get("output"),
            "reasoning": totals.get("reasoning"),
            "cached_input": totals.get("cached_input"),
            "calls": totals.get("calls"),
        },
        "cost_usd": (summary.get("cost_computation") or {}).get("total_cost_usd"),
        "cost_source": (summary.get("cost_computation") or {}).get("status"),
        "app_ts_sha256": sha256_file(app_ts),
        "app_ts_bytes": app_ts.stat().st_size if app_ts.is_file() else None,
        "app_ts_lines": (
            len(app_ts.read_text(encoding="utf-8", errors="replace").splitlines())
            if app_ts.is_file()
            else None
        ),
        "smoke": {
            "ok": smoke.get("ok"),
            "stage": smoke.get("stage"),
            "port": smoke.get("port"),
            "status_code": smoke.get("status_code"),
            "error": smoke.get("error"),
        }
        if smoke
        else None,
        "flow": {
            "ok": flow.get("ok"),
            "stage": flow.get("stage"),
            "happy_path_passed": flow.get("happy_path_passed"),
            "happy_path_total": flow.get("happy_path_total"),
            "negative_passed": flow.get("negative_passed"),
            "negative_total": flow.get("negative_total"),
            "error": flow.get("error"),
        }
        if flow
        else None,
    }
    return rec


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    done = [r for r in records if r.get("status") == "completed"]
    by_case: Dict[str, Dict[str, Any]] = {}
    for r in records:
        c = by_case.setdefault(
            r["case"],
            {
                "runs": 0,
                "completed": 0,
                "converged": 0,
                "smoke_ok": 0,
                "flow_ok": 0,
                "failed": 0,
                "json_violations": 0,
                "iterations": [],
                "cost_usd": 0.0,
            },
        )
        c["runs"] += 1
        c["json_violations"] += ((r.get("protocol_violations") or {})
                                 .get("tasker_json_parse_failures") or 0)
        if r.get("status") != "completed":
            c["failed"] += 1
        if r.get("status") == "completed":
            c["completed"] += 1
            if r.get("converged"):
                c["converged"] += 1
            if (r.get("smoke") or {}).get("ok"):
                c["smoke_ok"] += 1
            if (r.get("flow") or {}).get("ok"):
                c["flow_ok"] += 1
            if r.get("iterations"):
                c["iterations"].append(r["iterations"])
            c["cost_usd"] = round(c["cost_usd"] + (r.get("cost_usd") or 0.0), 6)
    for c in by_case.values():
        its = c["iterations"]
        c["mean_iterations"] = round(sum(its) / len(its), 2) if its else None

    return {
        "runs_total": len(records),
        "runs_completed": len(done),
        "runs_converged": sum(1 for r in done if r.get("converged")),
        "runs_smoke_ok": sum(1 for r in done if (r.get("smoke") or {}).get("ok")),
        "runs_flow_ok": sum(1 for r in done if (r.get("flow") or {}).get("ok")),
        "runs_failed": sum(1 for r in records if r.get("status") != "completed"),
        "failures_by_cause": {
            cause: sum(1 for r in records if r.get("failure_cause") == cause)
            for cause in ("model", "infrastructure", "configuration", "unknown")
            if any(r.get("failure_cause") == cause for r in records)
        },
        "retried_runs": sum(1 for r in records if (r.get("attempts") or 0) > 1),
        "tasker_json_parse_failures": sum(
            ((r.get("protocol_violations") or {}).get("tasker_json_parse_failures") or 0)
            for r in records
        ),
        "tasker_json_hard_failures": sum(
            ((r.get("protocol_violations") or {}).get("tasker_json_hard_failures") or 0)
            for r in records
        ),
        "total_cost_usd": round(sum(r.get("cost_usd") or 0.0 for r in records), 6),
        "total_input_tokens": sum((r.get("tokens") or {}).get("input") or 0 for r in records),
        "total_output_tokens": sum((r.get("tokens") or {}).get("output") or 0 for r in records),
        "total_reasoning_tokens": sum((r.get("tokens") or {}).get("reasoning") or 0 for r in records),
        "by_case": by_case,
    }


def main() -> int:
    args = parse_args()
    if args.archive_legacy:
        archive_legacy(args)

    planned = plan_runs(args)
    log(f"planned {len(planned)} runs across {len({p['case'] for p in planned})} cases, concurrency={args.concurrency}")

    if args.dry_run:
        for job in planned:
            state = "complete" if is_complete(job["_out"]) else "pending"
            print(f"  {job['run_id']:<48} {state:<9} <- {job['requirements']}")
        return 0

    started = time.time()
    records: List[Dict[str, Any]] = []
    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        pending = {pool.submit(execute, job, args): job for job in planned}
        for fut in futures.as_completed(pending):
            job = pending[fut]
            try:
                records.append(fut.result())
            except Exception as e:
                log(f"ERROR {job['run_id']}: {type(e).__name__}: {e}")
                records.append(
                    {k: v for k, v in job.items() if not k.startswith("_")}
                    | {"status": "error", "error": f"{type(e).__name__}: {e}"}
                )

    if _abort.is_set():
        log("=" * 72)
        log("BATCH ABORTED: a credentials or model-id fault was detected.")
        log("Fix the configuration and re-run; completed runs are reused automatically.")

    records.sort(key=lambda r: (r["case"], r["run_index"]))
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "software": args.software,
        "output_root": args.output_root,
        "config": {
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "temperature_requested": args.temperature,
            "seed": None,
            "max_iters": args.max_iters,
            "runs_per_case": args.runs,
            "concurrency": args.concurrency,
            "retries": args.retries,
            "smoke_test": args.smoke_test,
            "flow_test": args.flow_test,
        },
        "batch_wall_seconds": round(time.time() - started, 2),
        "summary": summarize(records),
        "runs": records,
    }

    path = REPO / args.output_root / args.software / "batch_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    s = manifest["summary"]
    log("=" * 72)
    log(
        f"completed {s['runs_completed']}/{s['runs_total']} | converged {s['runs_converged']}"
        f" | smoke ok {s['runs_smoke_ok']}"
        + (f" | flow ok {s['runs_flow_ok']}" if args.flow_test else "")
    )
    log(f"tokens in={s['total_input_tokens']:,} out={s['total_output_tokens']:,} (reasoning {s['total_reasoning_tokens']:,})")
    log(f"cost ${s['total_cost_usd']:.4f} | wall {manifest['batch_wall_seconds'] / 60:.1f} min")
    if s.get("runs_failed"):
        log(f"failures {s['runs_failed']} by cause {s.get('failures_by_cause')} | retried {s.get('retried_runs')}")
    if s.get("tasker_json_parse_failures"):
        log(
            f"protocol: tasker JSON parse failures {s['tasker_json_parse_failures']} "
            f"(unrecoverable {s['tasker_json_hard_failures']})"
        )
    log(f"manifest -> {path.relative_to(REPO)}")

    return 0 if s["runs_completed"] == s["runs_total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
