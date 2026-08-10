"""
Screenshot capture for the inclusivity evaluation.

The inclusivity rubric is scored from screenshots ("Using the screenshots
provided, evaluate each of the 15 statements"), so every artifact must be walked
through its recovery journey in a real browser and photographed at each step.

Why the walkthrough is model-derived
------------------------------------
Each run invents its own interface. Observed across artifacts: server-rendered
<form> elements in one, a DOM built entirely in JavaScript with no forms at all
in another, journeys of four to six steps, and mock verification codes that are
printed into an on-page log element and must be read back and typed into the
next field. No fixed selector script survives that variety, so a model reads
app.ts and emits a click-through plan.

Unlike the flow test, the judgement here is not pass/fail — it is a set of
images. A plan that stalls still yields the screenshots taken up to that point,
and the run is recorded as partial rather than discarded.
"""

import json
import pathlib
import re
from typing import Any, Dict, List, Optional

from app.utils.parsing import extract_json_object
from app.utils.smoke import smoke_test

VIEWPORT = {"width": 1280, "height": 800}
# Generous: case-3 artifacts deliberately avoid time pressure and may animate or
# stage their transitions, so a tight timeout reads as a stall.
ACTION_TIMEOUT_MS = 12000
STEP_SETTLE_MS = 400
MAX_SOURCE_CHARS = 220_000

UI_PROMPT = """\
You are scripting a browser walkthrough of a password-recovery web application,
so that each step of the user journey can be screenshotted for an accessibility
review. The full server source follows.

Produce a plan that walks the COMPLETE journey a user takes, in order, exactly
as a person would: request a recovery code, enter it, choose a new password,
sign in, complete any second-factor step, and any later steps the app supports
(accepting privacy conditions, confirming an appointment).

Reply with ONLY a JSON object, no prose and no code fences:

{
  "variables": {"email": "<seeded account identifier from the source>",
                "new_password": "<a password satisfying the app's stated policy>"},
  "steps": [
    {"name": "login_page", "actions": []},
    {"name": "request_password_reset",
     "actions": [
       {"do": "click", "selector": "text=Forgot your password?"},
       {"do": "fill",  "selector": "#email", "value": "${email}"},
       {"do": "click", "selector": "button:has-text('Send')"}
     ]}
  ]
}

Action types:
  {"do": "click",    "selector": "<playwright selector>"}
  {"do": "fill",     "selector": "<selector>", "value": "<text or ${var}>"}
  {"do": "read",     "selector": "<selector>", "regex": "<one capture group>", "into": "<var>"}
  {"do": "wait_for", "selector": "<selector>"}
  {"do": "wait_ms",  "ms": 500}

Rules:
  - A screenshot is taken at the END of every step, so each step should leave the
    page showing one meaningful stage of the journey. Name steps in snake_case
    after what is visible, e.g. "verify_reset_code", "set_new_password".
  - The first step is normally the landing page with no actions.
  - Mock codes: this app simulates delivery by printing the recovery code or
    second-factor code into an element on the page (often a log or console area).
    Use "read" with a regex to pull it out, then "fill" it into the next input.
    Look in the source for what exactly gets logged, and match that text.
  - Prefer robust selectors: text=, :has-text(), role/label based, or an id that
    genuinely appears in the source. The interface is built by this source only.
  - Some inputs are pre-filled by the app; do not overwrite a pre-filled value
    unless the user would type over it.
  - Use only selectors, field names and routes that actually exist in the source.
  - Do not include steps that require leaving the application.

SOURCE:
```typescript
{source}
```
"""

REPAIR_PROMPT = """\
The walkthrough plan you produced failed at step "{step}" on action {action}.

Error: {error}

This is the HTML actually rendered at that moment:
```html
{html}
```

Return the SAME JSON plan, corrected from that step onward so it matches the real
DOM. Keep the steps that already succeeded unchanged. Reply with ONLY the JSON.
"""


def derive_ui_script(source: str, llm, extra_context: str = "") -> Dict[str, Any]:
    """Ask the model to read app.ts and emit a browser walkthrough plan."""
    prompt = UI_PROMPT.replace("{source}", source[:MAX_SOURCE_CHARS])
    if extra_context:
        prompt += "\n\nAdditional context about this app's API journey:\n" + extra_context
    resp = llm.invoke([{"role": "user", "content": prompt}])
    content = resp.content
    if isinstance(content, list):
        content = "".join(
            p.get("text", "") if isinstance(p, dict) else str(p) for p in content
        )
    return extract_json_object(str(content))


def _interpolate(value: Any, variables: Dict[str, Any]) -> str:
    text = str(value)
    return re.sub(
        r"\$\{(\w+)\}", lambda m: str(variables.get(m.group(1), m.group(0))), text
    )


def _do_action(page, action: Dict[str, Any], variables: Dict[str, Any]) -> None:
    kind = action.get("do")
    selector = action.get("selector")

    if kind == "click":
        page.click(selector, timeout=ACTION_TIMEOUT_MS)
    elif kind == "fill":
        page.fill(selector, _interpolate(action.get("value", ""), variables),
                  timeout=ACTION_TIMEOUT_MS)
    elif kind == "wait_for":
        page.wait_for_selector(selector, timeout=ACTION_TIMEOUT_MS)
    elif kind == "wait_ms":
        page.wait_for_timeout(int(action.get("ms", 500)))
    elif kind == "read":
        # Mock codes are printed into the page rather than delivered, so they
        # must be scraped back out before the next field can be filled.
        text = page.inner_text(selector, timeout=ACTION_TIMEOUT_MS)
        pattern = action.get("regex") or r"([A-Za-z0-9_-]{4,})"
        found = re.search(pattern, text)
        if not found:
            raise RuntimeError(
                f"regex {pattern!r} found nothing in {selector!r} (text: {text[:120]!r})"
            )
        variables[action.get("into", "code")] = (
            found.group(1) if found.groups() else found.group(0)
        )
    else:
        raise RuntimeError(f"unknown action type {kind!r}")


def dom_inventory(page) -> Dict[str, Any]:
    """
    What the interface actually offers, read from the live DOM.

    Deriving a walkthrough from source alone is guesswork: some artifacts render
    every stage into one page and reveal sections progressively, so a heading
    exists in the DOM long before it is visible and a naive wait_for on it
    stalls. Grounding the plan in the real elements avoids that.
    """
    js_text = "els => els.map(e => e.textContent.trim()).filter(Boolean).slice(0,25)"
    return {
        "title": page.title(),
        "headings": page.eval_on_selector_all("h1,h2,h3", js_text),
        "buttons": page.eval_on_selector_all("button", js_text),
        "links": page.eval_on_selector_all("a", js_text),
        "inputs": page.eval_on_selector_all(
            "input,select,textarea",
            "els => els.map(e => ({id:e.id, type:e.type, label:e.getAttribute('aria-label')||'', "
            "placeholder:e.placeholder||'', visible: !!(e.offsetWidth||e.offsetHeight)}))",
        ),
        "forms": page.eval_on_selector_all("form", "els => els.length"),
        "visible_headings": page.eval_on_selector_all(
            "h1,h2,h3",
            "els => els.filter(e => !!(e.offsetWidth||e.offsetHeight))"
            ".map(e => e.textContent.trim()).slice(0,10)",
        ),
    }


def capture_journey(
    base_url: str, spec: Dict[str, Any], out_dir: pathlib.Path
) -> Dict[str, Any]:
    """Walk the plan in Chromium, screenshotting after each step."""
    from playwright.sync_api import sync_playwright

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("step_*.png"):
        stale.unlink()

    variables = dict(spec.get("variables") or {})
    steps = spec.get("steps") or []
    shots: List[Dict[str, Any]] = []
    failure: Optional[Dict[str, Any]] = None

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        # Artifacts serve over TLS with a local mkcert certificate.
        context = browser.new_context(
            viewport=VIEWPORT, ignore_https_errors=True, locale="en-GB"
        )
        page = context.new_page()
        console_errors: List[str] = []
        page.on("pageerror", lambda e: console_errors.append(str(e)[:200]))

        try:
            page.goto(base_url + "/", timeout=20000, wait_until="domcontentloaded")
        except Exception as e:
            browser.close()
            return {
                "ok": False,
                "stage": "navigation_failed",
                "error": f"{type(e).__name__}: {e}",
                "screenshots": [],
            }

        for index, step in enumerate(steps, start=1):
            name = re.sub(r"[^a-z0-9_]+", "_", str(step.get("name", f"step{index}")).lower())
            action: Optional[Dict[str, Any]] = None
            try:
                for action in step.get("actions") or []:
                    _do_action(page, action, variables)
                page.wait_for_timeout(STEP_SETTLE_MS)
            except Exception as e:
                failure = {
                    "step": step.get("name"),
                    "index": index,
                    "action": action,
                    "error": f"{type(e).__name__}: {str(e)[:200]}",
                    "html": page.content()[:6000],
                }
                # Still photograph the stalled state: it is evidence, and the
                # steps already captured remain usable for scoring.
                shot = out_dir / f"step_{index:02d}_{name}_INCOMPLETE.png"
                try:
                    page.screenshot(path=str(shot), full_page=True)
                    shots.append({"index": index, "name": name, "file": shot.name,
                                  "incomplete": True})
                except Exception:
                    pass
                break

            shot = out_dir / f"step_{index:02d}_{name}.png"
            page.screenshot(path=str(shot), full_page=True)
            shots.append({"index": index, "name": name, "file": shot.name,
                          "incomplete": False})

        browser.close()

    return {
        "ok": failure is None and len(shots) > 0,
        "stage": "complete" if failure is None else "partial",
        "steps_planned": len(steps),
        "steps_captured": len(shots),
        "screenshots": shots,
        "console_errors": console_errors[:5],
        "failure": failure,
    }


def capture(
    run_dir: str,
    llm,
    out_dir: str,
    certs_src: Optional[str] = None,
    reuse_spec: bool = True,
    repair: bool = True,
) -> Dict[str, Any]:
    """
    Derive a walkthrough for run_dir/app.ts, boot it, and photograph the journey.

    Reuses smoke_test's boot, port-discovery and cross-process locking so the
    artifact is never started twice or raced against a sibling capture.
    """
    run_path = pathlib.Path(run_dir)
    out_path = pathlib.Path(out_dir)
    app_path = run_path / "app.ts"
    spec_path = run_path / "ui_script.json"
    result_path = run_path / "capture.json"

    if not app_path.is_file():
        result = {"ok": False, "stage": "missing_artifact", "screenshots": []}
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    source = app_path.read_text(encoding="utf-8", errors="replace")

    # The flow spec already established the journey and the demo credentials.
    flow_spec = run_path / "flow_spec.json"
    context = ""
    if flow_spec.is_file():
        try:
            context = json.dumps(json.loads(flow_spec.read_text()), indent=1)[:4000]
        except Exception:
            context = ""

    cached_spec = None
    if reuse_spec and spec_path.is_file():
        try:
            cached_spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except Exception:
            cached_spec = None

    state: Dict[str, Any] = {}

    def on_ready(base_url: str, ports: List[int]) -> Dict[str, Any]:
        """
        Best-of-N. Each attempt writes to its own staging directory and only the
        best is promoted, so a weaker retry can never destroy a better capture —
        which a plain overwrite did, replacing 7 good screenshots with 2.
        """
        staging = out_path.parent / f".{out_path.name}_attempt"
        attempts: List[Dict[str, Any]] = []

        # Read the real interface before planning against it.
        from playwright.sync_api import sync_playwright

        inventory: Dict[str, Any] = {}
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport=VIEWPORT, ignore_https_errors=True)
                page = ctx.new_page()
                page.goto(base_url + "/", timeout=20000, wait_until="domcontentloaded")
                page.wait_for_timeout(800)
                inventory = dom_inventory(page)
                browser.close()
        except Exception:
            inventory = {}
        state["inventory"] = inventory

        grounded = context
        if inventory:
            grounded += (
                "\n\nThe live DOM of GET / offers exactly these elements. Plan only "
                "against them, and note that an element present here may still be "
                "hidden until earlier steps reveal it:\n"
                + json.dumps(inventory, indent=1)[:4000]
            )

        spec = cached_spec
        if spec is None:
            try:
                spec = derive_ui_script(source, llm, grounded)
            except Exception as e:
                return {"ok": False, "stage": "script_derivation_failed",
                        "error": f"{type(e).__name__}: {e}", "screenshots": [],
                        "steps_captured": 0, "steps_planned": 0}

        def try_plan(plan: Dict[str, Any], label: str) -> Dict[str, Any]:
            work = pathlib.Path(f"{staging}_{len(attempts) + 1}")
            outcome = capture_journey(base_url, plan, work)
            outcome["_dir"], outcome["_plan"], outcome["_label"] = work, plan, label
            attempts.append(outcome)
            return outcome

        outcome = try_plan(spec, "initial")

        # Repair: hand the model the DOM as it actually rendered at the point of
        # failure and let it correct the plan from there.
        if repair and not outcome["ok"] and outcome.get("failure"):
            fail = outcome["failure"]
            try:
                fixed = derive_ui_script(
                    source,
                    llm,
                    grounded
                    + "\n\n"
                    + REPAIR_PROMPT.format(
                        step=fail.get("step"), action=json.dumps(fail.get("action")),
                        error=fail.get("error"), html=fail.get("html", "")[:6000],
                    ),
                )
            except Exception:
                fixed = None
            if fixed:
                outcome = try_plan(fixed, "repaired")

        # Still short: one independent re-derivation. Plan quality varies between
        # samples, so a fresh attempt sometimes clears a step the others cannot.
        if not outcome["ok"]:
            try:
                fresh = derive_ui_script(source, llm, grounded)
                outcome = try_plan(fresh, "rederived")
            except Exception:
                pass

        best = max(attempts, key=lambda a: (a["ok"], a["steps_captured"]))
        if out_path.exists():
            for stale in out_path.glob("step_*.png"):
                stale.unlink()
        out_path.mkdir(parents=True, exist_ok=True)
        for png in sorted(best["_dir"].glob("step_*.png")):
            png.replace(out_path / png.name)
        for a in attempts:
            if a["_dir"].exists():
                for leftover in a["_dir"].glob("*"):
                    leftover.unlink()
                a["_dir"].rmdir()

        state["chosen"] = best["_label"]
        state["attempts"] = [
            {"label": a["_label"], "ok": a["ok"], "captured": a["steps_captured"]}
            for a in attempts
        ]
        if best["_label"] != "initial":
            spec_path.write_text(
                json.dumps(best["_plan"], ensure_ascii=False, indent=2), encoding="utf-8"
            )
        for key in ("_dir", "_plan", "_label"):
            best.pop(key, None)
        return best

    smoke = smoke_test(
        run_dir, certs_src=certs_src, on_ready=on_ready, write_result=False
    )

    if not smoke.get("ok"):
        result = {
            "ok": False,
            "stage": f"server_{smoke.get('stage')}",
            "error": smoke.get("error"),
            "screenshots": [],
        }
    else:
        result = smoke.get("on_ready_result") or {
            "ok": False, "stage": "no_result", "screenshots": []
        }
    result["chosen_attempt"] = state.get("chosen")
    result["attempts"] = state.get("attempts")
    result["output_dir"] = str(out_path)
    result_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result
