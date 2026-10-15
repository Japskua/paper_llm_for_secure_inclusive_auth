# Publishing this repository on Zenodo

How this dataset is archived to Zenodo and cited in the paper.

| | |
|---|---|
| Zenodo record | <https://doi.org/10.5281/zenodo.18472957> |
| **Concept DOI** — cite this | `10.5281/zenodo.18472957`, always resolves to the newest version |
| Versions | `v.1.0.1` (2026-02-03, the 2025 single-run study) · `v.2.0.0` (2026-10-15, the repeated-runs study) |

## What gets archived

Zenodo archives a snapshot of the GitHub repository at each release. The tracked
content is ~69 MB packed, comfortably inside Zenodo's 50 GB limit, and includes:

| | |
|---|---|
| `generations/` | the 60 artifacts, generation traces, verification results, 509 screenshots |
| `final_evaluations/results_v2/` | 2,457 judgements, tidy CSVs, per-study and cross-study analysis |
| `final_evaluations/results/` | the 2025 single-run collection, unchanged |
| `human_evaluations/`, `survey_questionnaires/` | expert results and the instruments used |
| `human_evaluation_package/` | the six best artifacts, packaged for human review |
| pipeline and analysis scripts | `run_batch.py`, `run_capture.py`, `run_judge.py`, `analyse.py`, `report.py`, `build_workbook.py`, `app/` |

Not archived, deliberately: `.venv/`, `node_modules/`, `.env`, and TLS
certificates (`certs/`, `*.pem`). Certificates are local development artefacts
and are regenerated with `mkcert` — see the root README.

## Zenodo–GitHub link

Already in place: `v.1.0.1` was archived automatically, so every new GitHub
release becomes a new version under the same concept DOI. Nothing needs setting
up. If archiving ever stops, check that
**`Japskua/paper_llm_for_secure_inclusive_auth`** is still switched **On** at
<https://zenodo.org/account/settings/github/>.

`.zenodo.json` supplies the title, authors, affiliations, keywords, licence and
description, so nothing is typed into the Zenodo web form. Author names follow
the form already on the record (e.g. `Shahid, Waleed Bin`); keep them identical
across versions.

## Making a release

```bash
git checkout main && git pull

# Sanity-check the state of the data before freezing it
uv run python report.py                 # regenerates every cross-study table
uv run python build_workbook.py         # regenerates all_results.xlsx
git status --short                      # must be clean

# Tags follow the existing form: v.MAJOR.MINOR.PATCH
git tag -a v.2.0.0 -m "Two user stories, 10 runs per case, 7-judge panel"
git push origin v.2.0.0
gh release create v.2.0.0 \
  --title "v.2.0.0 — repeated-runs study, two user stories" \
  --notes-file RELEASE_NOTES.md
```

Zenodo picks the release up within a few minutes and adds it as a new version,
with its own **version DOI**, under the existing concept DOI. Nothing in the
repository needs updating afterwards: the README badge, `CITATION.cff` and the
BibTeX all use the concept DOI.

For the paper's data availability statement:

> The complete dataset, generation pipeline and analysis scripts are openly
> available at <https://doi.org/10.5281/zenodo.18472957>.

## Versioning

| Change | Action |
|---|---|
| New data collected, or numbers change | new release, minor or major bump |
| Analysis script changed such that outputs differ | new release |
| Documentation, typos, DOI badge | commit to `main`, no release |

Each release adds a version to the same Zenodo record. Never delete a published
version — reviewers may already have cited it.

## Before releasing, check

- [ ] `report.py` and `build_workbook.py` re-run cleanly and leave no diff
- [ ] no API keys anywhere: `git grep -nE "sk-or-|sk-[A-Za-z0-9]{20,}"` is empty
- [ ] `final_evaluations/results_v2/README.md` matches the data it describes
- [ ] `human_evaluation_package/source_code/MANIFEST.csv` hashes still verify
- [ ] `CITATION.cff` `version` and `date-released` updated, in `v.X.Y.Z` form
- [ ] `.zenodo.json` `version` matches the tag exactly
- [ ] author names unchanged from the previous version
