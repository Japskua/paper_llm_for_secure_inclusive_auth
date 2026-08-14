# Publishing this repository and minting a DOI

How this dataset is archived to Zenodo and cited in the paper. Follow it in
order; the DOI cannot exist before the first release.

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

## One-time setup

1. Sign in at <https://zenodo.org> with the GitHub account that owns the
   repository, or link the accounts under **Account → Linked accounts → GitHub**.
2. Open <https://zenodo.org/account/settings/github/> and switch
   **`Japskua/paper_llm_for_secure_inclusive_auth`** to **On**.
   Zenodo now watches for GitHub releases. Releases created *before* this switch
   are not archived, so do this first.
3. Confirm `.zenodo.json` in the repository root is current. It supplies the
   title, authors, affiliations, keywords, licence and description, so nothing
   has to be typed into the Zenodo web form.

## Making a release

```bash
git checkout main && git pull

# Sanity-check the state of the data before freezing it
uv run python report.py                 # regenerates every cross-study table
uv run python build_workbook.py         # regenerates all_results.xlsx
git status --short                      # must be clean

git tag -a v2.0.0 -m "Two user stories, 10 runs per case, 7-judge panel"
git push origin v2.0.0
gh release create v2.0.0 \
  --title "v2.0.0 — repeated-runs study, two user stories" \
  --notes-file RELEASE_NOTES.md
```

Zenodo picks the release up within a few minutes and mints two DOIs:

- a **concept DOI** that always resolves to the newest version — **cite this one
  in the paper**;
- a **version DOI** for this exact release, for anyone reproducing the specific
  numbers.

## After the DOI exists

1. Replace the placeholder badge at the top of `README.md`:

   ```markdown
   [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)
   ```

   Use the **concept** DOI.
2. Add `doi:` and `identifiers:` to `CITATION.cff`, and fill in the `TBA`
   citation blocks in `README.md` and `final_evaluations/README.md`.
3. Commit as `Add Zenodo DOI` — it does **not** need a new release. The archived
   snapshot keeps the placeholder; that is normal and harmless.
4. Add to the paper's data availability statement:

   > The complete dataset, generation pipeline and analysis scripts are openly
   > available at <https://doi.org/10.5281/zenodo.XXXXXXX>.

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
- [ ] `CITATION.cff` version and `date-released` updated
- [ ] `.zenodo.json` version updated to match the tag
