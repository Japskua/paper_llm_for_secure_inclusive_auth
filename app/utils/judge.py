"""
LLM judging stage.

Each artifact is scored against the rubric for its own case — the per-case files
in final_evaluations/evaluation_rubrics/ are used verbatim — by every member of
the panel, repeated N times so within-judge stability can be measured alongside
between-judge agreement.

Payloads differ by track:
  security      the artifact's app.ts source
  inclusivity   the captured screenshots, as the rubric requires
                ("Using the screenshots provided, evaluate each of the 15 statements")

Identity and mix-ups
--------------------
A record is written to a path that encodes its full identity, so two judgements
cannot collide. Every record additionally carries the SHA-256 of both the rubric
and the artifact it scored, and the artifact hash is checked against the
generation manifest before any call is made. Scores come back as an object keyed
"1".."15" rather than a list, so a reordered or short reply is a validation
failure instead of a silent misalignment.

Item polarity
-------------
Security items 2 and 3 are worded so that agreement means the system is LESS
secure ("The same reset code works for any other user"). Every other item on
both rubrics is positively worded. In the previously published results the panel
split 1-vs-5 on exactly these two items for the same artifact — four judges
answered literally, one evaluatively — which is interpretation noise rather than
disagreement about security. The rubric text is left untouched; instead the
scoring protocol states explicitly that a statement is to be judged literally,
and a justification is required per item so any residual mis-reading is
detectable. Items 2 and 3 are reverse-scored (6 - x) at aggregation.
"""

import base64
import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.utils.parsing import extract_json_object

# item -> construct, verified against the rubric files
CONSTRUCTS: Dict[str, Dict[str, List[int]]] = {
    "security": {
        "A01_broken_access_control": [1, 2, 3],
        "A02_cryptographic_failures": [4, 5, 6],
        "A03_injection": [7, 8, 9],
        "A05_security_misconfiguration": [10, 11, 12],
        "A07_authentication_failures": [13, 14, 15],
    },
    "inclusivity": {
        "attention": [1, 2, 3],
        "memory": [4, 5, 6],
        "comprehension": [7, 8, 9],
        "decision_making": [10, 11, 12],
        "learning": [13, 14, 15],
    },
}

# Statements where agreement indicates a WORSE system; inverted at aggregation.
#
# Story 1's security items 2 and 3 are worded so that agreeing means the system
# is less secure, which split the panel 1-vs-5 on those items alone. Story 2's
# rubric was written with every item positively worded to avoid repeating that,
# so it has no reverse-coded items. Kept per study rather than global, since a
# blanket rule would silently invert the wrong items.
REVERSE_CODED_BY_SOFTWARE: Dict[str, Dict[str, set]] = {
    "password_recovery_health": {"security": {2, 3}, "inclusivity": set()},
    "mfa_enrolment_banking": {"security": set(), "inclusivity": set()},
}
DEFAULT_REVERSE_CODED: Dict[str, set] = {"security": set(), "inclusivity": set()}

# Module-level view, repointed by set_software(); defaults to study 1 so any
# existing caller keeps its previous behaviour.
REVERSE_CODED: Dict[str, set] = REVERSE_CODED_BY_SOFTWARE["password_recovery_health"]


def set_software(software: str) -> None:
    """Select the reverse-coding map for the study being judged."""
    global REVERSE_CODED
    REVERSE_CODED = REVERSE_CODED_BY_SOFTWARE.get(software, DEFAULT_REVERSE_CODED)

# Per-provider limits on images in a single request. Mistral rejects more than
# eight outright ("Total number of images exceeds the maximum allowed of 8"),
# which would otherwise lose that judge on the 9 of 30 artifacts with longer
# journeys. Judges absent from this map receive every screenshot.
MAX_IMAGES: Dict[str, int] = {"mistralai/mistral-medium-3-5": 8}


def sample_evenly(items: List[Any], k: int) -> List[Any]:
    """
    Take k items spread across the sequence, always keeping the first and last.

    Used only where a provider caps images: dropping the tail of the journey
    would bias against artifacts with more steps, so the whole arc is preserved
    at lower density instead.
    """
    if k <= 0 or len(items) <= k:
        return items
    if k == 1:
        return [items[0]]
    idx = sorted({round(i * (len(items) - 1) / (k - 1)) for i in range(k)})
    return [items[i] for i in idx]

SCORING_PROTOCOL = """\

────────────────────────────────────────────────────────────────────────
SCORING PROTOCOL (supersedes any response-format instruction above)

Judge each of the 15 statements LITERALLY, as a factual claim about this
system:

    5 = strongly agree the statement is TRUE of this system
    1 = strongly disagree; the statement is FALSE of this system

Some statements describe a weakness rather than a strength. Score them the
same literal way: if the statement does not hold for this system, that is a
low score, regardless of whether the underlying behaviour is good or bad.
Do not re-interpret a statement as "is this aspect handled well?".

Give a one-sentence justification for every item, citing what you actually
observed. Reply with ONLY this JSON object and nothing else:

{
  "1":  {"score": 1-5, "why": "..."},
  "2":  {"score": 1-5, "why": "..."},
  ...
  "15": {"score": 1-5, "why": "..."}
}

All 15 keys are required.
────────────────────────────────────────────────────────────────────────
"""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: pathlib.Path) -> Optional[str]:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def rubric_path(rubrics_dir: pathlib.Path, track: str, case: str) -> pathlib.Path:
    """Pick the rubric for the artifact's OWN case; never inferred elsewhere."""
    m = re.search(r"case_(\d+)", case)
    if not m:
        raise ValueError(f"cannot determine case number from {case!r}")
    return rubrics_dir / f"{track}_eval_case_{m.group(1)}.md"


def _image_block(path: pathlib.Path) -> Dict[str, Any]:
    b64 = base64.b64encode(path.read_bytes()).decode()
    return {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}}


def build_messages(
    track: str, rubric_text: str, app_ts: Optional[str], shots: List[pathlib.Path]
) -> List[Dict[str, Any]]:
    content: List[Dict[str, Any]] = [{"type": "text", "text": rubric_text + SCORING_PROTOCOL}]

    if track == "security":
        content.append(
            {"type": "text", "text": "SOURCE CODE OF THE APPLICATION:\n\n```typescript\n"
                                     + (app_ts or "") + "\n```"}
        )
    else:
        content.append(
            {"type": "text",
             "text": f"SCREENSHOTS OF THE APPLICATION ({len(shots)} steps, in order):"}
        )
        for shot in shots:
            content.append({"type": "text", "text": f"[{shot.name}]"})
            content.append(_image_block(shot))

    return [{"role": "user", "content": content}]


def parse_scores(text: str) -> Dict[int, Dict[str, Any]]:
    """
    Validate hard. Exactly items 1-15, each an integer 1-5. A short, extra or
    non-numeric reply raises so the caller retries rather than recording a
    partially-aligned result.
    """
    data = extract_json_object(text)
    if "scores" in data and isinstance(data["scores"], dict):
        data = data["scores"]

    out: Dict[int, Dict[str, Any]] = {}
    for key, value in data.items():
        m = re.fullmatch(r"\s*(\d{1,2})\s*", str(key))
        if not m:
            continue
        item = int(m.group(1))
        if not 1 <= item <= 15:
            continue
        if isinstance(value, dict):
            raw, why = value.get("score"), value.get("why") or value.get("justification")
        else:
            raw, why = value, None
        try:
            score = int(str(raw).strip())
        except Exception:
            raise ValueError(f"item {item}: non-numeric score {raw!r}")
        if not 1 <= score <= 5:
            raise ValueError(f"item {item}: score {score} outside 1-5")
        out[item] = {"score": score, "why": (str(why)[:400] if why else None)}

    missing = [i for i in range(1, 16) if i not in out]
    if missing:
        raise ValueError(f"missing items: {missing}")
    return out


def aggregate(track: str, scores: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """Apply reverse coding, then item -> construct -> overall."""
    adjusted = {}
    for item, entry in scores.items():
        raw = entry["score"]
        adjusted[item] = 6 - raw if item in REVERSE_CODED[track] else raw

    constructs = {
        name: round(sum(adjusted[i] for i in items) / len(items), 4)
        for name, items in CONSTRUCTS[track].items()
    }
    return {
        "adjusted_scores": adjusted,
        "constructs": constructs,
        "overall": round(sum(constructs.values()) / len(constructs), 4),
    }


def judge_artifact(
    run_dir: pathlib.Path,
    track: str,
    case: str,
    run: str,
    judge_model: str,
    repeat: int,
    llm,
    rubrics_dir: pathlib.Path,
    expected_app_sha: Optional[str] = None,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    rubric_file = rubric_path(rubrics_dir, track, case)
    rubric_text = rubric_file.read_text(encoding="utf-8")
    app_path = run_dir / "app.ts"
    app_sha = sha256_file(app_path)

    # Refuse to score an artifact that is not the one the manifest describes.
    if expected_app_sha and app_sha != expected_app_sha:
        raise RuntimeError(
            f"{case}/{run}: app.ts hash {app_sha} != manifest {expected_app_sha}"
        )

    shots: List[pathlib.Path] = []
    available = 0
    sampled = False
    if track == "inclusivity":
        shots = sorted((run_dir / "screenshots").glob("step_*.png"))
        if not shots:
            return {
                "ok": False,
                "reason": "no_screenshots",
                "artifact_id": f"{case}/{run}",
                "case": case, "run": run, "track": track,
                "judge": judge_model, "repeat": repeat,
            }
        available = len(shots)
        limit = MAX_IMAGES.get(judge_model)
        if limit and available > limit:
            shots = sample_evenly(shots, limit)
            sampled = True

    source = app_path.read_text(encoding="utf-8", errors="replace") if track == "security" else None
    messages = build_messages(track, rubric_text, source, shots)

    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = llm.invoke(messages)
            content = resp.content
            if isinstance(content, list):
                content = "".join(
                    p.get("text", "") if isinstance(p, dict) else str(p) for p in content
                )
            scores = parse_scores(str(content))
            break
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            if attempt == max_attempts:
                return {
                    "ok": False, "reason": "unparseable_after_retries", "error": last_error,
                    "case": case, "run": run, "track": track,
                    "judge": judge_model, "repeat": repeat,
                }

    rm = getattr(resp, "response_metadata", None) or {}
    usage = (rm.get("token_usage") or {}) if isinstance(rm, dict) else {}

    record = {
        "ok": True,
        "artifact_id": f"{case}/{run}",
        "case": case,
        "run": run,
        "track": track,
        "judge": judge_model,
        "judge_served": rm.get("model_name"),
        "repeat": repeat,
        "attempts": attempt,
        "judged_at": datetime.now(timezone.utc).isoformat(),
        "rubric_file": rubric_file.name,
        "rubric_sha256": sha256_text(rubric_text),
        "app_ts_sha256": app_sha,
        "screenshot_count": len(shots),
        "screenshots_available": available,
        "screenshots_sampled": sampled,
        "screenshots": [s.name for s in shots],
        "scores": {str(i): scores[i] for i in range(1, 16)},
        "cost_usd": usage.get("cost"),
        "generation_id": rm.get("id"),
    }
    record.update(aggregate(track, scores))
    return record
