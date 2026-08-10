#!/usr/bin/env python
"""
Statistical analysis of the judging results (Phase 2, step 3).

Aggregation order, fixed before the results were seen:

    item -> construct (mean of its 3 items)
         -> judgement (mean of the 5 constructs)
         -> judge      (mean over the 3 repeats)
         -> artifact   (MEDIAN over the 7 judges, robust to one odd judge)
         -> case       (mean +/- SD over the 10 artifacts)

The artifact score is the unit of analysis, giving n=10 per case, so the primary
test does not treat 1239 judgements as independent observations when they are
seven opinions about thirty things.

Outputs a printed report plus CSVs under final_evaluations/results_v2/analysis/.
"""

import argparse
import itertools
import pathlib
import sys
import warnings

import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore")

REPO = pathlib.Path(__file__).resolve().parent
RESULTS = REPO / "final_evaluations" / "results_v2"
OUT = RESULTS / "analysis"

def generator_lab() -> str:
    """
    The lab whose model generated the artifacts. A judge from that lab is not an
    independent rater of its own lab's output, so it is analysed as a separate
    stratum rather than pooled into the panel.
    """
    import json
    m = json.loads((REPO / "generations" / "password_recovery_health"
                    / "batch_manifest.json").read_text())
    return str(m["config"]["model"]).split("/")[0]


CASE_LABEL = {
    "case_1_multi_no_condition_no_inclusion": "1 no condition",
    "case_2_multi_condition_no_inclusion": "2 ADHD mentioned",
    "case_3_multi_condition_with_inclusion": "3 detailed guidance",
}


def rule(char: str = "-", n: int = 78) -> None:
    print(char * n)


def head(title: str) -> None:
    print()
    rule("=")
    print(title)
    rule("=")


# ---------------------------------------------------------------- reliability
def krippendorff_alpha(matrix: np.ndarray) -> float:
    """
    Krippendorff's alpha, interval metric. Rows are units (artifacts), columns
    raters (judges); NaN marks a missing rating.

    Chosen alongside ICC because it tolerates the missing cells that arise when
    an artifact cannot be scored at all, without dropping the whole row.
    """
    units = [row[~np.isnan(row)] for row in matrix]
    units = [u for u in units if len(u) >= 2]
    if not units:
        return float("nan")

    n = sum(len(u) for u in units)
    if n < 2:
        return float("nan")

    observed = 0.0
    for u in units:
        m = len(u)
        pairs = sum((a - b) ** 2 for a, b in itertools.permutations(u, 2))
        observed += pairs / (m - 1)
    observed /= n

    allv = np.concatenate(units)
    expected = sum((a - b) ** 2 for a, b in itertools.permutations(allv, 2))
    expected /= n * (n - 1)

    return float("nan") if expected == 0 else 1 - observed / expected


def icc2k(wide: pd.DataFrame) -> float:
    """ICC(2,k): absolute agreement of the mean of k raters, two-way random."""
    data = wide.dropna()
    if data.shape[0] < 2 or data.shape[1] < 2:
        return float("nan")
    x = data.values
    n, k = x.shape
    grand = x.mean()
    ms_rows = k * ((x.mean(axis=1) - grand) ** 2).sum() / (n - 1)
    ms_cols = n * ((x.mean(axis=0) - grand) ** 2).sum() / (k - 1)
    resid = x - x.mean(axis=1, keepdims=True) - x.mean(axis=0, keepdims=True) + grand
    ms_err = (resid ** 2).sum() / ((n - 1) * (k - 1))
    denom = ms_rows + (ms_cols - ms_err) / n
    return float("nan") if denom == 0 else (ms_rows - ms_err) / denom


# ------------------------------------------------------------- effect / tests
def epsilon_squared(groups) -> float:
    """Effect size for Kruskal-Wallis; 0.01 small, 0.08 medium, 0.26 large."""
    n = sum(len(g) for g in groups)
    if n <= 1:
        return float("nan")
    h = stats.kruskal(*groups).statistic
    return float(h / ((n ** 2 - 1) / (n + 1)))


def cliffs_delta(a, b) -> float:
    a, b = np.asarray(a), np.asarray(b)
    gt = sum((x > b).sum() for x in a)
    lt = sum((x < b).sum() for x in a)
    return (gt - lt) / (len(a) * len(b))


def compare_cases(df: pd.DataFrame, track: str, label: str) -> list:
    sub = df[df.track == track]
    groups, names = [], []
    for case in sorted(sub.case.unique()):
        groups.append(sub[sub.case == case].artifact_score.values)
        names.append(case)
    if len(groups) < 2:
        return []

    h, p = stats.kruskal(*groups)
    eps = epsilon_squared(groups)
    print(f"\n  {label} — Kruskal-Wallis across the three cases")
    print(f"    H = {h:.3f}, p = {p:.4f}, epsilon^2 = {eps:.3f} "
          f"({'large' if eps >= .26 else 'medium' if eps >= .08 else 'small'} effect)")
    print(f"    n per case: {[len(g) for g in groups]}")

    rows = []
    pairs = list(itertools.combinations(range(len(groups)), 2))
    raw = []
    for i, j in pairs:
        u, pu = stats.mannwhitneyu(groups[i], groups[j], alternative="two-sided")
        raw.append(pu)
    # Holm correction
    order = np.argsort(raw)
    adj = np.empty(len(raw))
    for rank, idx in enumerate(order):
        adj[idx] = min(1.0, raw[idx] * (len(raw) - rank))
    adj = np.maximum.accumulate(adj[order])[np.argsort(order)]

    print(f"    {'pair':<44}{'p (Holm)':>10}{'Cliff d':>10}")
    for (i, j), p_adj in zip(pairs, adj):
        d = cliffs_delta(groups[i], groups[j])
        mark = " *" if p_adj < 0.05 else ""
        print(f"    {CASE_LABEL[names[i]]:<20} vs {CASE_LABEL[names[j]]:<20}"
              f"{p_adj:>10.4f}{d:>10.2f}{mark}")
        rows.append({"track": track, "case_a": names[i], "case_b": names[j],
                     "p_holm": round(float(p_adj), 5), "cliffs_delta": round(d, 4),
                     "median_a": float(np.median(groups[i])),
                     "median_b": float(np.median(groups[j]))})
    return rows


# ---------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pool-generator-lab", action="store_true",
                    help="Pool the generator's own lab into the primary panel "
                         "(default: analysed as a separate stratum)")
    ap.add_argument("--exclude-sampled", action="store_true",
                    help="Drop judgements where screenshots were capped to 8")
    ap.add_argument("--complete-capture-only", action="store_true",
                    help="Drop artifacts whose journey capture was partial")
    ap.add_argument("--drop-degenerate", action="store_true",
                    help="Drop judge/track combinations that cannot discriminate between artifacts")
    ap.add_argument("--degenerate-sd", type=float, default=0.05,
                    help="Artifact-level SD below which a judge is treated as degenerate")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    jdf = pd.read_csv(RESULTS / "scores_artifact.csv")

    lab = generator_lab()
    jdf["panel"] = np.where(jdf.judge.str.startswith(lab + "/"),
                            "generator_lab", "independent")

    note = []
    if args.pool_generator_lab:
        jdf["panel"] = "independent"
        note.append(f"{lab} pooled into the primary panel")
    if args.exclude_sampled and "screenshots_sampled" in jdf.columns:
        jdf = jdf[~jdf.screenshots_sampled.astype(str).isin(["True", "true"])]
        note.append("screenshot-capped judgements excluded")
    if args.complete_capture_only:
        keep = jdf[(jdf.track == "inclusivity")].groupby("artifact_id").screenshot_count.max()
        partial = set(keep[keep < 6].index)
        jdf = jdf[~jdf.artifact_id.isin(partial)]
        note.append(f"{len(partial)} partially-captured artifacts excluded")

    # A judge whose artifact-level scores have almost no spread is not rating the
    # artifacts, it is emitting a fixed pattern. Such a rater adds no information
    # and actively depresses agreement statistics, so it is identified explicitly
    # rather than silently averaged in.
    degenerate = []
    for track in jdf.track.unique():
        for judge in jdf.judge.unique():
            sub = jdf[(jdf.track == track) & (jdf.judge == judge)]
            if sub.empty:
                continue
            spread = sub.groupby("artifact_id").overall.mean().std()
            if spread < args.degenerate_sd:
                degenerate.append((judge, track, float(spread)))
    if degenerate and args.drop_degenerate:
        for judge, track, _ in degenerate:
            jdf = jdf[~((jdf.judge == judge) & (jdf.track == track))]
        note.append(f"{len(degenerate)} degenerate judge/track combination(s) dropped")

    head("DATASET")
    print(f"  judgements            : {len(jdf)}")
    print(f"  artifacts             : {jdf.artifact_id.nunique()}")
    print(f"  judges                : {jdf.judge.nunique()}")
    print(f"  repeats per judge     : {sorted(jdf.repeat.unique())}")
    print(f"  generator lab         : {lab} (generated the artifacts under test)")
    for cls in ("independent", "generator_lab"):
        js = sorted(jdf[jdf.panel == cls].judge.unique())
        if js:
            print(f"  {cls:<22}: {len(js)} judge(s) — {', '.join(j.split('/')[-1] for j in js)}")
    if note:
        print(f"  filters applied       : {', '.join(note)}")
    if degenerate:
        print()
        print("  NON-DISCRIMINATING JUDGES (artifact-level SD below "
              f"{args.degenerate_sd}):")
        for judge, track, spread in degenerate:
            state = "dropped" if args.drop_degenerate else "RETAINED - rerun with --drop-degenerate"
            print(f"    {judge} on {track}: SD={spread:.4f}  [{state}]")

    # judge -> artifact -> case, per the pre-registered order
    per_judge = (jdf.groupby(["artifact_id", "case", "track", "judge", "panel"],
                             as_index=False)
                    .overall.mean().rename(columns={"overall": "judge_score"}))

    def to_artifact(src: pd.DataFrame) -> pd.DataFrame:
        return (src.groupby(["artifact_id", "case", "track"], as_index=False)
                   .judge_score.median()
                   .rename(columns={"judge_score": "artifact_score"}))

    # Primary scores come from the independent panel only: the generator's own
    # lab cannot be an impartial rater of its lab's output.
    independent = per_judge[per_judge.panel == "independent"]
    artifact = to_artifact(independent)
    gen_only = per_judge[per_judge.panel == "generator_lab"]
    artifact_gen = to_artifact(gen_only) if not gen_only.empty else pd.DataFrame()

    head("CASE MEANS  (artifact score = median across judges, mean across repeats)")
    print(f"  {'case':<24}{'track':<14}{'n':>3}{'mean':>8}{'SD':>7}{'median':>8}{'min':>7}{'max':>7}")
    summary = []
    for track in ("security", "inclusivity"):
        for case in sorted(artifact.case.unique()):
            v = artifact[(artifact.track == track) & (artifact.case == case)].artifact_score
            if not len(v):
                continue
            print(f"  {CASE_LABEL[case]:<24}{track:<14}{len(v):>3}{v.mean():>8.2f}"
                  f"{v.std():>7.2f}{v.median():>8.2f}{v.min():>7.2f}{v.max():>7.2f}")
            summary.append({"case": case, "track": track, "n": len(v),
                            "mean": round(v.mean(), 4), "sd": round(v.std(), 4),
                            "median": round(v.median(), 4)})
        print()
    pd.DataFrame(summary).to_csv(OUT / "case_summary.csv", index=False)

    head("CONSTRUCT BREAKDOWN  (mean across judgements)")
    cons = [c for c in jdf.columns if c.startswith("c_")]
    for track in ("security", "inclusivity"):
        sub = jdf[jdf.track == track]
        cols = [c for c in cons if sub[c].notna().any()]
        if not cols:
            continue
        print(f"\n  {track}")
        table = sub.groupby("case")[cols].mean().round(2)
        table.index = [CASE_LABEL[i] for i in table.index]
        table.columns = [c[2:] for c in table.columns]
        print(table.to_string().replace("\n", "\n  "))
        table.to_csv(OUT / f"constructs_{track}.csv")

    head("JUDGE RELIABILITY")
    rel = []
    for track in ("security", "inclusivity"):
        wide = (per_judge[per_judge.track == track]
                .pivot(index="artifact_id", columns="judge", values="judge_score"))
        icc = icc2k(wide)
        alpha = krippendorff_alpha(wide.values)
        rhos = [stats.spearmanr(wide[a], wide[b], nan_policy="omit").statistic
                for a, b in itertools.combinations(wide.columns, 2)]
        # within-judge stability across the 3 repeats
        within = (jdf[jdf.track == track]
                  .groupby(["artifact_id", "judge"]).overall.std().mean())
        print(f"\n  {track}")
        print(f"    ICC(2,k) agreement of the 7-judge mean : {icc:.3f}")
        print(f"    Krippendorff alpha (interval)          : {alpha:.3f}")
        print(f"    mean pairwise Spearman between judges  : {np.nanmean(rhos):.3f}")
        print(f"    within-judge SD across 3 repeats       : {within:.3f}")
        rel.append({"track": track, "icc2k": round(icc, 4),
                    "krippendorff_alpha": round(alpha, 4),
                    "mean_pairwise_spearman": round(float(np.nanmean(rhos)), 4),
                    "within_judge_sd": round(float(within), 4)})
    pd.DataFrame(rel).to_csv(OUT / "reliability.csv", index=False)

    head("JUDGE SEVERITY  (mean overall by judge)")
    sev = jdf.pivot_table(index="judge", columns="track", values="overall", aggfunc="mean").round(2)
    print(sev.to_string().replace("\n", "\n  "))
    sev.to_csv(OUT / "judge_severity.csv")

    if not artifact_gen.empty:
        head("SELF-PREFERENCE  (generator's lab vs the independent panel)")
        merged = artifact.merge(
            artifact_gen, on=["artifact_id", "case", "track"],
            suffixes=("_independent", "_generator"))
        merged["bias"] = merged.artifact_score_generator - merged.artifact_score_independent
        print("  Positive bias = the generator's lab scores its own lab's output")
        print("  higher than the independent panel does.\n")
        print(f"  {'track':<14}{'n':>4}{'independent':>13}{'generator':>11}"
              f"{'bias':>8}{'Wilcoxon p':>12}{'rho':>7}")
        rows = []
        for track in ("security", "inclusivity"):
            sub = merged[merged.track == track]
            if len(sub) < 3:
                continue
            try:
                _, pw = stats.wilcoxon(sub.artifact_score_generator,
                                       sub.artifact_score_independent)
            except Exception:
                pw = float("nan")
            rho = stats.spearmanr(sub.artifact_score_generator,
                                  sub.artifact_score_independent).statistic
            mark = " *" if pw < 0.05 else ""
            print(f"  {track:<14}{len(sub):>4}{sub.artifact_score_independent.mean():>13.2f}"
                  f"{sub.artifact_score_generator.mean():>11.2f}{sub.bias.mean():>8.2f}"
                  f"{pw:>12.4f}{rho:>7.2f}{mark}")
            rows.append({"track": track, "n": len(sub),
                         "mean_independent": round(sub.artifact_score_independent.mean(), 4),
                         "mean_generator_lab": round(sub.artifact_score_generator.mean(), 4),
                         "mean_bias": round(sub.bias.mean(), 4),
                         "wilcoxon_p": round(float(pw), 5),
                         "spearman_rho": round(float(rho), 4)})
        print("\n  Does the bias vary by case? A bias that grows with the")
        print("  manipulation would inflate the very comparison being tested.")
        print(f"  {'track':<14}{'case':<24}{'mean bias':>11}")
        for track in ("security", "inclusivity"):
            sub = merged[merged.track == track]
            for case in sorted(sub.case.unique()):
                b = sub[sub.case == case].bias
                print(f"  {track:<14}{CASE_LABEL[case]:<24}{b.mean():>11.2f}")
            groups = [sub[sub.case == c].bias.values for c in sorted(sub.case.unique())]
            if len(groups) > 2 and all(len(g) > 1 for g in groups):
                _, pk = stats.kruskal(*groups)
                print(f"  {track:<14}{'-> bias differs by case?':<24}{'p=' + format(pk, '.4f'):>11}")
        pd.DataFrame(rows).to_csv(OUT / "self_preference.csv", index=False)

    head("CASE COMPARISON  (primary test — independent panel, n=10 per case)")
    pairs = []
    pairs += compare_cases(artifact, "security", "SECURITY")
    pairs += compare_cases(artifact, "inclusivity", "INCLUSIVITY")
    pd.DataFrame(pairs).to_csv(OUT / "case_comparisons.csv", index=False)

    if not artifact_gen.empty:
        head("CASE COMPARISON  (generator's lab alone — reported, not pooled)")
        gpairs = []
        gpairs += compare_cases(artifact_gen, "security", "SECURITY (generator lab)")
        gpairs += compare_cases(artifact_gen, "inclusivity", "INCLUSIVITY (generator lab)")
        pd.DataFrame(gpairs).to_csv(OUT / "case_comparisons_generator_lab.csv", index=False)

    artifact.to_csv(OUT / "artifact_scores.csv", index=False)
    head("FILES")
    for f in sorted(OUT.glob("*.csv")):
        print(f"  {f.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
