#!/usr/bin/env python
"""
Cross-study reporting: every number, raw and derived, for both user stories.

Sections
  1  Dataset counts            what exists, per study
  2  Case summaries            mean / median / SD / range per case and track
  3  Medians across the runs   the per-case median asked for in reporting
  4  Construct breakdowns      5 constructs x 3 cases, per track and study
  5  Best run per case         candidates for human evaluation
  6  Judge-by-judge scores     every judge's mean per case, both studies
  7  OpenAI vs the rest        the generator's lab against the independent panel
  8  Judge reliability         ICC, Krippendorff alpha, Spearman, repeat SD
  9  Cross-study differences   story 1 against story 2, per case and track
 10  Artifact health           convergence, boot, client script, screenshots

Aggregation follows the pre-registered order used in analyse.py:
    item -> construct -> judgement -> judge (mean over repeats)
         -> artifact (median over judges) -> case

Everything printed is also written to CSV under
final_evaluations/results_v2/cross_study/.

    uv run python report.py                 both studies, all sections
    uv run python report.py --working-only  restrict to artifacts that run
"""

import argparse
import glob
import itertools
import json
import pathlib
import sys
import warnings

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from analyse import cliffs_delta, epsilon_squared, icc2k, krippendorff_alpha  # noqa: E402

warnings.filterwarnings("ignore")

REPO = pathlib.Path(__file__).resolve().parent
RESULTS = REPO / "final_evaluations" / "results_v2"
OUT = RESULTS / "cross_study"

STUDIES = {
    "password_recovery_health": "Story 1 - password recovery, ADHD",
    "mfa_enrolment_banking": "Story 2 - MFA enrolment, dyslexia",
}
CASE = {
    "case_1_multi_no_condition_no_inclusion": "1 no condition",
    "case_2_multi_condition_no_inclusion": "2 condition named",
    "case_3_multi_condition_with_inclusion": "3 detailed guidance",
}
TRACKS = ("security", "inclusivity")
_tables: dict = {}


def emit(name: str, df: pd.DataFrame, show: bool = True) -> pd.DataFrame:
    _tables[name] = df
    if show:
        print(df.to_string(index=False).replace("\n", "\n  "))
    return df


def head(n: int, title: str) -> None:
    print()
    print("=" * 100)
    print(f"{n}.  {title}")
    print("=" * 100)


def load(study: str) -> pd.DataFrame:
    """Judgement-level scores, annotated with artifact health."""
    df = pd.read_csv(RESULTS / study / "scores_artifact.csv")
    df["study"] = study
    health = {}
    for d in glob.glob(str(REPO / "generations" / study / "case_*" / "run_*")):
        p = pathlib.Path(d)
        rec = {}
        try:
            s = json.loads((p / "smoke.json").read_text())
            rec["http_ok"] = bool(s.get("ok"))
            rec["client_ok"] = s.get("client_ok")
        except Exception:
            rec["http_ok"] = rec["client_ok"] = None
        try:
            t = json.loads((p / "tokens_summary.json").read_text())["run"]
            rec["converged"] = t.get("converged")
            rec["iterations"] = t.get("iterations")
        except Exception:
            pass
        rec["shots"] = len(list((p / "screenshots").glob("step_*.png")))
        health["/".join(p.parts[-2:])] = rec
    for col in ("http_ok", "client_ok", "converged", "iterations", "shots"):
        df[col] = df.artifact_id.map(lambda a: (health.get(a) or {}).get(col))
    return df


def to_artifact(df: pd.DataFrame, judges: str = "independent") -> pd.DataFrame:
    """judgement -> judge mean over repeats -> artifact median over judges."""
    sub = df
    if judges == "independent":
        sub = df[~df.judge.str.startswith("openai/")]
    elif judges == "openai":
        sub = df[df.judge.str.startswith("openai/")]
    per_judge = (sub.groupby(["study", "artifact_id", "case", "track", "judge"], as_index=False)
                    .overall.mean())
    return (per_judge.groupby(["study", "artifact_id", "case", "track"], as_index=False)
                     .overall.median().rename(columns={"overall": "artifact_score"}))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--working-only", action="store_true",
                    help="Restrict to artifacts whose client script runs")
    ap.add_argument("--keep-degenerate", action="store_true",
                    help="Keep judge/track combinations that cannot discriminate "
                         "between artifacts (default: dropped, matching analyse.py)")
    ap.add_argument("--degenerate-sd", type=float, default=0.05)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    raw = pd.concat([load(s) for s in STUDIES], ignore_index=True)
    if args.working_only:
        # Drop only artifacts KNOWN to be broken. Story 1 is frozen and predates
        # the client-script check, so its artifacts are unknown rather than
        # broken; excluding them would silently remove that whole study.
        broken = raw[raw.client_ok == False]  # noqa: E712
        names = sorted(set(zip(broken.study, broken.artifact_id)))
        raw = raw[raw.client_ok != False]  # noqa: E712
        print(f"FILTER: {len(names)} artifact(s) with a known-dead client script excluded")
        for s, a in names:
            print(f"  - {STUDIES[s][:8]}  {a}")
        print("  story 1 has no client-script signal (frozen, predates the check), "
              "so it is unfiltered here")

    # Match analyse.py: a judge whose artifact-level scores barely vary is not
    # rating the artifacts and only depresses the agreement statistics. Dropped
    # by default here so this report and analyse.py cannot disagree.
    degenerate = []
    for study in raw.study.unique():
        for track in TRACKS:
            for judge in raw.judge.unique():
                s = raw[(raw.study == study) & (raw.track == track) & (raw.judge == judge)]
                if s.empty:
                    continue
                spread = s.groupby("artifact_id").overall.mean().std()
                if spread < args.degenerate_sd:
                    degenerate.append((study, track, judge, float(spread)))
    if degenerate:
        print("NON-DISCRIMINATING judge/track combinations "
              f"(artifact-level SD < {args.degenerate_sd}):")
        for study, track, judge, sd in degenerate:
            state = "kept" if args.keep_degenerate else "DROPPED"
            print(f"  {STUDIES[study][:8]:<9} {track:<12} {judge:<30} SD={sd:.4f}  [{state}]")
        if not args.keep_degenerate:
            for study, track, judge, _ in degenerate:
                raw = raw[~((raw.study == study) & (raw.track == track) & (raw.judge == judge))]

    art = to_artifact(raw)
    art["case_label"] = art.case.map(CASE)

    # ---------------------------------------------------------------- 1
    head(1, "DATASET COUNTS")
    rows = []
    for study in STUDIES:
        d = raw[raw.study == study]
        rows.append({
            "study": STUDIES[study], "artifacts": d.artifact_id.nunique(),
            "judges": d.judge.nunique(), "repeats": d.repeat.nunique(),
            "judgements": len(d), "item_scores": len(d) * 15,
            "security_judgements": (d.track == "security").sum(),
            "inclusivity_judgements": (d.track == "inclusivity").sum(),
        })
    total = {k: (sum(r[k] for r in rows) if k != "study" else "BOTH STUDIES") for k in rows[0]}
    total["judges"] = rows[0]["judges"]; total["repeats"] = rows[0]["repeats"]
    emit("01_dataset_counts", pd.DataFrame(rows + [total]))

    # ---------------------------------------------------------------- 2 & 3
    head(2, "CASE SUMMARIES  (artifact score: median over judges, mean over repeats)")
    rows = []
    for study in STUDIES:
        for track in TRACKS:
            for case in sorted(CASE):
                v = art[(art.study == study) & (art.track == track) & (art.case == case)].artifact_score
                if not len(v):
                    continue
                rows.append({
                    "study": STUDIES[study][:8], "track": track, "case": CASE[case],
                    "n": len(v), "mean": round(v.mean(), 3), "median": round(v.median(), 3),
                    "sd": round(v.std(), 3), "min": round(v.min(), 3), "max": round(v.max(), 3),
                    "iqr": round(v.quantile(.75) - v.quantile(.25), 3),
                })
    emit("02_case_summary", pd.DataFrame(rows))

    head(3, "MEDIAN PER CASE ACROSS THE RUNS  (headline reporting table)")
    piv = (pd.DataFrame(rows).pivot_table(index=["study", "case"], columns="track",
                                          values="median")
           .reset_index().rename(columns={"security": "security_median",
                                          "inclusivity": "inclusivity_median"}))
    emit("03_case_medians", piv)

    # ---------------------------------------------------------------- 4
    head(4, "CONSTRUCT BREAKDOWN  (mean across judgements)")
    print("  Security constructs are identical across studies, so those columns are")
    print("  comparable. Inclusivity constructs are NOT: the studies target different")
    print("  cognitive conditions and name different dimensions, so they are shown apart.")
    for track in TRACKS:
        for study in STUDIES:
            d = raw[(raw.track == track) & (raw.study == study)]
            cols = [c for c in d.columns if c.startswith("c_") and d[c].notna().any()]
            if not cols:
                continue
            tab = d.groupby("case")[cols].mean().round(3).reset_index()
            tab["case"] = tab.case.map(CASE)
            tab.columns = [c[2:] if c.startswith("c_") else c for c in tab.columns]
            print(f"\n  --- {track}: {STUDIES[study]} ---")
            emit(f"04_constructs_{track}_{study}", tab)

    # ---------------------------------------------------------------- 5
    head(5, "BEST RUN PER CASE  (candidates for human evaluation)")
    print("  combined = mean of the security and inclusivity artifact scores\n")
    wide = art.pivot_table(index=["study", "artifact_id", "case"], columns="track",
                           values="artifact_score").reset_index()
    wide["combined"] = wide[list(TRACKS)].mean(axis=1)
    # artifact_id is not unique across studies (both use case_N/run_NN), so the
    # health join must be keyed on study as well or the two collide.
    meta = (raw.drop_duplicates(["study", "artifact_id"])
               .set_index(["study", "artifact_id"]))
    for col in ("client_ok", "converged", "iterations", "shots"):
        wide[col] = [meta[col].get((s, a)) for s, a in zip(wide.study, wide.artifact_id)]
    best = (wide.sort_values("combined", ascending=False)
                .groupby(["study", "case"], as_index=False).head(1)
                .sort_values(["study", "case"]))
    best["study"] = best.study.map(lambda s: STUDIES[s][:8]); best["case"] = best.case.map(CASE)
    # story 1 predates the client-script check and is frozen, so it has no value
    best["client_ok"] = best.client_ok.map(lambda v: {True: "yes", False: "NO"}.get(v, "n/a"))
    emit("05_best_run_per_case", best[["study", "case", "artifact_id", "security",
                                       "inclusivity", "combined", "client_ok",
                                       "converged", "iterations", "shots"]].round(3))
    emit("05b_all_artifacts_ranked",
         wide.sort_values(["study", "case", "combined"], ascending=[True, True, False]).round(3),
         show=False)

    # ---------------------------------------------------------------- 6
    head(6, "JUDGE BY JUDGE  (mean overall per case)")
    for study in STUDIES:
        d = raw[raw.study == study]
        t = (d.groupby(["judge", "track", "case"]).overall.mean().round(2)
             .unstack("case").reset_index())
        t.columns = [CASE.get(c, c) for c in t.columns]
        print(f"\n  --- {STUDIES[study]} ---")
        emit(f"06_judges_{study}", t)

    # ---------------------------------------------------------------- 7
    head(7, "OPENAI (generator's lab) vs THE INDEPENDENT PANEL")
    rows = []
    for study in STUDIES:
        d = raw[raw.study == study]
        ind = to_artifact(d, "independent").rename(columns={"artifact_score": "panel"})
        oai = to_artifact(d, "openai").rename(columns={"artifact_score": "openai"})
        m = ind.merge(oai, on=["study", "artifact_id", "case", "track"])
        for track in TRACKS:
            s = m[m.track == track]
            if len(s) < 3:
                continue
            try:
                _, pw = stats.wilcoxon(s.openai, s.panel)
            except Exception:
                pw = float("nan")
            rows.append({
                "study": STUDIES[study][:8], "track": track, "n": len(s),
                "panel_mean": round(s.panel.mean(), 3), "openai_mean": round(s.openai.mean(), 3),
                "bias": round((s.openai - s.panel).mean(), 3),
                "wilcoxon_p": round(float(pw), 4),
                "spearman_rho": round(float(stats.spearmanr(s.openai, s.panel).statistic), 3),
                "pearson_r": round(float(stats.pearsonr(s.openai, s.panel).statistic), 3),
            })
    emit("07_openai_vs_panel", pd.DataFrame(rows))

    # ---------------------------------------------------------------- 8
    head(8, "JUDGE RELIABILITY")
    rows = []
    for study in STUDIES:
        d = raw[raw.study == study]
        for track in TRACKS:
            pj = (d[d.track == track]
                  .groupby(["artifact_id", "judge"], as_index=False).overall.mean())
            w = pj.pivot(index="artifact_id", columns="judge", values="overall")
            rhos = [stats.spearmanr(w[a], w[b], nan_policy="omit").statistic
                    for a, b in itertools.combinations(w.columns, 2)]
            rows.append({
                "study": STUDIES[study][:8], "track": track,
                "icc_2k": round(icc2k(w), 3),
                "krippendorff_alpha": round(krippendorff_alpha(w.values), 3),
                "mean_pairwise_spearman": round(float(np.nanmean(rhos)), 3),
                "within_judge_sd": round(float(
                    d[d.track == track].groupby(["artifact_id", "judge"]).overall.std().mean()), 3),
            })
    emit("08_reliability", pd.DataFrame(rows))

    # ---------------------------------------------------------------- 9
    head(9, "CROSS-STUDY DIFFERENCES  (story 2 minus story 1)")
    rows = []
    for track in TRACKS:
        for case in sorted(CASE):
            a = art[(art.study == "password_recovery_health") & (art.track == track)
                    & (art.case == case)].artifact_score
            b = art[(art.study == "mfa_enrolment_banking") & (art.track == track)
                    & (art.case == case)].artifact_score
            if len(a) < 2 or len(b) < 2:
                continue
            u, p = stats.mannwhitneyu(a, b, alternative="two-sided")
            rows.append({
                "track": track, "case": CASE[case], "n_s1": len(a), "n_s2": len(b),
                "story1_mean": round(a.mean(), 3), "story2_mean": round(b.mean(), 3),
                "difference": round(b.mean() - a.mean(), 3),
                "mannwhitney_p": round(float(p), 4),
                "cliffs_delta": round(cliffs_delta(b.values, a.values), 3),
            })
    emit("09_cross_study_differences", pd.DataFrame(rows))

    print("\n  Within-study case comparisons (the primary test in each study):")
    rows = []
    for study in STUDIES:
        for track in TRACKS:
            groups, names = [], []
            for case in sorted(CASE):
                g = art[(art.study == study) & (art.track == track)
                        & (art.case == case)].artifact_score.values
                if len(g) >= 2:
                    groups.append(g); names.append(case)
            if len(groups) < 2:
                continue
            h, p = stats.kruskal(*groups)
            row = {"study": STUDIES[study][:8], "track": track,
                   "n_per_case": str([len(g) for g in groups]),
                   "H": round(float(h), 3), "p": round(float(p), 4),
                   "epsilon_sq": round(epsilon_squared(groups), 3)}
            for i, j in itertools.combinations(range(len(groups)), 2):
                _, pu = stats.mannwhitneyu(groups[i], groups[j], alternative="two-sided")
                key = f"{CASE[names[i]][0]}v{CASE[names[j]][0]}"
                row[key + "_p"] = round(float(pu), 4)
                row[key + "_d"] = round(cliffs_delta(groups[i], groups[j]), 2)
            rows.append(row)
    emit("09b_within_study_tests", pd.DataFrame(rows))

    # ---------------------------------------------------------------- 10
    head(10, "ARTIFACT HEALTH")
    rows = []
    for study in STUDIES:
        d = raw[raw.study == study].drop_duplicates("artifact_id")
        for case in sorted(CASE):
            s = d[d.case == case]
            if not len(s):
                continue
            rows.append({
                "study": STUDIES[study][:8], "case": CASE[case], "artifacts": len(s),
                "converged": int(s.converged.sum()),
                "http_200": int(s.http_ok.sum()),
                # story 1 is frozen and predates the client-script check
                "client_live": (int((s.client_ok == True).sum())  # noqa: E712
                                if s.client_ok.notna().any() else "n/a"),
                "mean_iterations": round(s.iterations.mean(), 1),
                "mean_screenshots": round(s.shots.mean(), 1),
            })
    emit("10_artifact_health", pd.DataFrame(rows))

    for name, df in _tables.items():
        df.to_csv(OUT / f"{name}.csv", index=False)
    print(f"\n\n{len(_tables)} tables written to {OUT.relative_to(REPO)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
