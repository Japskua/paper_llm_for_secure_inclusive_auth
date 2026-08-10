"""
Parsers for agent output.

These were previously inline in app/pipeline/multi.py and tuned to how GPT-4o
happened to format its replies. They are extracted here so they can be unit
tested, and hardened against formatting differences across models:

  * Tasker JSON arrives wrapped in ``` fences or with a prose preamble.
  * Evaluator NEW_TASKS lists run past three items and contain blank lines.
  * Evaluator DECISION lines arrive as markdown, e.g. "**DECISION:** PASS".

Known behaviour change vs. the originally published pipeline: the old
NEW_TASKS parser accepted only "-", "1.", "2." and "3." prefixes and stopped at
the first blank line, so tasks 4+ were silently dropped. See README.
"""

import json
import re
from typing import Any, Dict, List, Optional

# Section headings emitted by the Evaluator (see prompts/prompt_evaluator.txt)
_SECTIONS = (
    "SUMMARY",
    "FUNCTIONAL_CHECK",
    "FAILING_ITEMS",
    "NEW_TASKS",
    "DECISION",
)

_LIST_ITEM = re.compile(r"^\s*(?:[-*+•]|\(?\d+[.)])\s+(.*\S)\s*$")
_FENCE = re.compile(r"^\s*```[a-zA-Z0-9_-]*\s*\n(.*?)\n\s*```\s*$", re.DOTALL)

_SENTINEL_TASKS = {"", "none", "none.", "n/a", "na", "no tasks", "no new tasks", "-"}


def _strip_md(text: str) -> str:
    """Remove markdown emphasis and heading/list decoration from a single line."""
    t = text.strip()
    t = re.sub(r"^[#>\s]*", "", t)
    t = re.sub(r"^(?:[-*+•]|\(?\d+[.)])\s+", "", t)
    t = t.replace("**", "").replace("__", "")
    t = re.sub(r"(?<!\w)[*_`]([^*_`]+)[*_`](?!\w)", r"\1", t)
    return t.strip()


def _section_of(line: str) -> Optional[str]:
    """
    Return the section name if this line is one of the Evaluator's headings.

    List items never count as headings, otherwise a task such as
    "- Summary panel must ..." would be mistaken for the SUMMARY section.
    """
    if _LIST_ITEM.match(line):
        return None
    cleaned = _strip_md(line).upper()
    for name in _SECTIONS:
        if cleaned.startswith(name):
            return name
    return None


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


# ---------------------------------------------------------------------------
# Tasker JSON
# ---------------------------------------------------------------------------
def _balanced_object(text: str) -> Optional[str]:
    """Extract the first balanced {...} block, ignoring braces inside strings."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def extract_json_object(text: str) -> Dict[str, Any]:
    """
    Parse a JSON object from a model reply.

    Tolerates ``` fences and surrounding prose. Raises ValueError if no valid
    object can be recovered, so the caller can retry with a corrective prompt.
    """
    candidates = []

    stripped = text.strip()
    candidates.append(stripped)

    fence = _FENCE.match(stripped)
    if fence:
        candidates.append(fence.group(1).strip())
    else:
        # Unterminated or inline fences
        without_fences = re.sub(r"```[a-zA-Z0-9_-]*", "", stripped).strip()
        if without_fences != stripped:
            candidates.append(without_fences)

    for candidate in list(candidates):
        block = _balanced_object(candidate)
        if block:
            candidates.append(block)

    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("No JSON object found in model output")


def parse_task_list(text: str) -> List[str]:
    """Extract task_list from the Tasker's JSON reply, filtering sentinel entries."""
    data = extract_json_object(text)
    raw = data.get("task_list", [])
    if not isinstance(raw, list):
        return []
    tasks = []
    for item in raw:
        task = _strip_md(str(item))
        if task.lower() not in _SENTINEL_TASKS:
            tasks.append(task)
    return tasks


# ---------------------------------------------------------------------------
# Evaluator output
# ---------------------------------------------------------------------------
def _new_tasks_section(md: str) -> List[str]:
    """Return the raw lines between the NEW_TASKS heading and the next section."""
    lines: List[str] = []
    in_section = False

    for line in (md or "").splitlines():
        section = _section_of(line)
        if section == "NEW_TASKS":
            in_section = True
            inline = _strip_md(line)[len("NEW_TASKS") :].lstrip(": ").strip()
            if inline:
                lines.append(inline)
            continue
        if in_section and section is not None:
            break  # reached the next section heading
        if in_section:
            lines.append(line)

    return lines


def parse_new_tasks(md: str) -> List[str]:
    """
    Extract the NEW_TASKS list from an Evaluator report.

    Evaluators commonly emit a hierarchy:

        1. Fix client script runtime errors
           1.1. Replace TypeScript assertions with plain property access
               - Change "(x as HTMLInputElement).value" to "x.value"
        2. Remove inline script

    Only outermost items count as tasks; nested items and continuation prose are
    folded into their parent so the Coder still receives the detail without the
    task count being inflated. Blank lines separate rather than terminate.
    """
    section = _new_tasks_section(md)
    items = [(i, ln) for i, ln in enumerate(section) if _LIST_ITEM.match(ln)]
    if not items:
        return []

    base_indent = min(_indent_of(ln) for _, ln in items)

    tasks: List[str] = []
    details: List[List[str]] = []

    for line in section:
        if not line.strip():
            continue
        match = _LIST_ITEM.match(line)
        if match and _indent_of(line) <= base_indent:
            tasks.append(_strip_md(match.group(1)))
            details.append([])
        elif tasks:
            # Nested item or wrapped prose belonging to the current task
            detail = _strip_md(line)
            if detail:
                details[-1].append(detail)

    out: List[str] = []
    for task, extra in zip(tasks, details):
        if task.lower() in _SENTINEL_TASKS:
            continue
        if extra:
            task = task + "\n" + "\n".join(f"  {d}" for d in extra)
        out.append(task)
    return out


def parse_decision(md: str) -> str:
    """
    Extract the Evaluator's PASS/FAIL verdict.

    Tolerates markdown emphasis and heading markers. Scans every candidate and
    keeps the last resolvable one, since DECISION is the final section in the
    Evaluator's output format. Defaults to FAIL when nothing parses.
    """
    lines = (md or "").splitlines()
    verdict = None

    for i, line in enumerate(lines):
        cleaned = _strip_md(line)
        if not cleaned.upper().startswith("DECISION"):
            continue

        rest = cleaned[len("DECISION") :].lstrip(": \t-—").strip()
        rest = _strip_md(rest).upper()
        if rest in {"PASS", "FAIL"}:
            verdict = rest
            continue

        # Verdict on the following non-empty line
        for j in range(i + 1, len(lines)):
            nxt = _strip_md(lines[j]).upper()
            if not nxt:
                continue
            if nxt in {"PASS", "FAIL"}:
                verdict = nxt
            break

    return verdict or "FAIL"


def is_pass(md: str) -> bool:
    return parse_decision(md) == "PASS"
