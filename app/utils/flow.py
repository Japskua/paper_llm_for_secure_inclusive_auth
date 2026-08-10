"""
Functional flow test for a generated app.ts.

The smoke test only proves the server boots and answers GET / — it says nothing
about whether the password-recovery feature works. This module walks the actual
journey (request code -> verify -> set password -> sign in -> MFA -> ...) and
checks a few security properties.

Why the contract is model-derived
---------------------------------
Every run invents its own API. Across the three validation artifacts alone:

    case 1  seven routes   /api/request-reset, /api/verify-token, ...
    case 2  one route      /api/recovery  (with 6 server-rendered forms)
    case 3  nine routes    /api/reset/request, /api/reset/verify, ...

A hardcoded probe would therefore pass on one run and fail on the next for
reasons that have nothing to do with artifact quality. So an LLM reads app.ts
and emits a call sequence; it never judges the outcome. Pass/fail comes solely
from executing real HTTP requests against the running server, so the verdict
stays objective even though the test plan is generated.
"""

import json
import pathlib
import re
from typing import Any, Dict, List, Optional

import httpx

from app.utils.parsing import extract_json_object
from app.utils.smoke import smoke_test

REQUEST_TIMEOUT_S = 20.0
MAX_SOURCE_CHARS = 220_000

SPEC_PROMPT = """\
You are writing an automated functional test for a self-contained
authentication-related web application. The complete source of the running
server follows.

Produce a test plan that exercises the FULL happy path a user would take through
whatever journey this application implements — read the source to discover what
that journey is, rather than assuming one — then a few negative checks. Read the
source carefully to determine:
  - the exact route paths and HTTP methods
  - the exact JSON field names each route expects
  - any seeded/demo account credentials (email, password) hardcoded in the source
  - how a CSRF token (if any) reaches the client, as a regex with ONE capture
    group that extracts it from the HTML of GET /
  - which response field carries a mock token / code that the next step needs

Reply with ONLY a JSON object, no prose and no code fences:

{
  "variables": {"email": "<seeded account email>", "new_password": "<a valid new password meeting the app's stated policy>"},
  "html_variables": {"<name>": "<regex with ONE capture group, applied to the HTML of GET />"},
  "csrf": {"html_regex": "<regex with one capture group>", "field": "<field or header name>", "in": "header" or "body"} or null,
  "steps": [
    {
      "name": "short human label",
      "method": "POST",
      "path": "/api/...",
      "body": {"field": "${email}"},
      "expect_json_true": "ok",
      "capture": {"token": "mockToken"}
    }
  ],
  "negative_steps": [
    {"name": "wrong password rejected", "method": "POST", "path": "/api/...",
     "body": {"...": "..."}, "expect_failure": true}
  ]
}

Rules:
  - For "csrf", set "in" to "header" when the client sends the token as an HTTP
    request header (e.g. X-CSRF-Token), or "body" when it is a JSON field.
    Check how the page's own fetch() calls send it. If the server requires a
    CSRF token on state-changing routes, "csrf" must NOT be null — find where
    the token reaches the page (an inline script constant, a meta tag, or a
    session/state endpoint) and describe it. If it arrives from a JSON endpoint
    rather than the HTML, make that endpoint the first step and capture the
    token into a variable named "csrf".
  - Use "html_variables" for any value that is generated at server start-up and
    shown to the user in the page (a pre-filled input value, a displayed
    reference code). Such values cannot be hardcoded because they change on
    every boot, so give a regex that extracts the value from the served HTML.
    Never emit a self-referential placeholder like "${x}" as the value of x.
  - "${name}" interpolates a variable captured earlier or defined in "variables".
  - "capture" maps a new variable name to a field in the JSON response
    (dotted paths allowed, e.g. "data.token").
  - "expect_json_true" names a response field that must be truthy for success.
    Omit it if the route signals success only by HTTP status.
  - "expect_failure": true means the step MUST NOT succeed (used for negatives).
  - Order "steps" so each one's prerequisites are satisfied by earlier steps.
  - Include every stage the application supports, to the end of its journey.
    Depending on the application this may involve signing in, requesting and
    entering a one-time code, setting or changing a credential, enrolling an
    authenticator, storing or regenerating backup codes, accepting conditions,
    or confirming a final action.
  - Use only routes and field names that actually appear in the source.

SOURCE:
```typescript
{source}
```
"""


def derive_flow_spec(source: str, llm) -> Dict[str, Any]:
    """Ask the model to read app.ts and emit a machine-executable call sequence."""
    prompt = SPEC_PROMPT.replace("{source}", source[:MAX_SOURCE_CHARS])
    resp = llm.invoke([{"role": "user", "content": prompt}])
    content = resp.content
    if isinstance(content, list):
        content = "".join(
            p.get("text", "") if isinstance(p, dict) else str(p) for p in content
        )
    return extract_json_object(str(content))


def _interpolate(value: Any, variables: Dict[str, Any]) -> Any:
    """Replace ${name} references, preserving non-string values."""
    if isinstance(value, str):
        match = re.fullmatch(r"\$\{(\w+)\}", value.strip())
        if match:  # whole-value reference keeps the original type
            return variables.get(match.group(1), value)
        return re.sub(
            r"\$\{(\w+)\}", lambda m: str(variables.get(m.group(1), m.group(0))), value
        )
    if isinstance(value, dict):
        return {k: _interpolate(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, variables) for v in value]
    return value


def _dig(data: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _run_step(
    client: httpx.Client,
    base_url: str,
    step: Dict[str, Any],
    variables: Dict[str, Any],
    csrf: Optional[Dict[str, Any]],
    csrf_value: Optional[str],
) -> Dict[str, Any]:
    method = (step.get("method") or "POST").upper()
    path = _interpolate(step.get("path", "/"), variables)
    body = _interpolate(step.get("body") or {}, variables)
    csrf_field = csrf.get("field", "csrf") if csrf else "csrf"
    csrf_in = (csrf.get("in") if csrf else None) or (
        "header" if "-" in csrf_field else "body"
    )
    headers: Dict[str, str] = {}
    declared = step.get("body") or {}

    # Token delivery varies widely: JSON body field, X-CSRF-Token header, or a
    # value fetched from a status endpoint rather than the HTML. Rather than
    # depend on the derived spec identifying it correctly, a positive step sends
    # the current token in every common form. Surplus fields and headers are
    # ignored by servers that do not use them, whereas a missing one fails the
    # request and would misreport a working artifact as broken.
    #
    # Negative steps are never auto-filled: they deliberately forge or omit the
    # token, and supplying a valid one would turn them into valid requests.
    if csrf_value and method != "GET" and not step.get("expect_failure"):
        for header_name in ("X-CSRF-Token", "X-Csrf-Token", "x-csrf-token"):
            headers.setdefault(header_name, csrf_value)
        if csrf_in == "header" and csrf_field not in headers:
            headers[csrf_field] = csrf_value
        if csrf_in != "header" and csrf_field not in declared:
            body = {**body, csrf_field: csrf_value}
        if "csrf" not in declared and "csrf" not in body:
            body = {**body, "csrf": csrf_value}

    # A negative step may name the header explicitly in order to forge it.
    if csrf_in == "header" and csrf_field in declared:
        headers = {k: v for k, v in headers.items() if k.lower() != csrf_field.lower()}
        headers[csrf_field] = str(body.pop(csrf_field, ""))

    record: Dict[str, Any] = {
        "name": step.get("name") or path,
        "method": method,
        "path": path,
        "expect_failure": bool(step.get("expect_failure")),
    }

    try:
        if method == "GET":
            resp = client.get(base_url + path, headers=headers or None)
        else:
            resp = client.request(
                method, base_url + path, json=body, headers=headers or None
            )
    except Exception as e:
        record.update(ok=False, error=f"{type(e).__name__}: {e}", status_code=None)
        record["ok"] = record["expect_failure"]  # a refused request is a valid rejection
        return record

    record["status_code"] = resp.status_code
    try:
        payload = resp.json()
    except Exception:
        payload = None

    succeeded = resp.status_code < 400
    flag = step.get("expect_json_true")
    if succeeded and flag:
        succeeded = bool(_dig(payload, flag)) if isinstance(payload, dict) else False
    elif succeeded and isinstance(payload, dict) and isinstance(payload.get("ok"), bool):
        # These apps routinely signal refusal as HTTP 200 with {"ok": false},
        # so status alone would read a rejection as a success — which matters
        # most for negative checks, where it inverts the verdict.
        succeeded = payload["ok"]

    if record["expect_failure"]:
        record["ok"] = not succeeded
    else:
        record["ok"] = succeeded
        for var, field in (step.get("capture") or {}).items():
            if isinstance(payload, dict):
                captured = _dig(payload, field)
                if captured is not None:
                    variables[var] = captured
                else:
                    record.setdefault("warnings", []).append(
                        f"could not capture '{var}' from '{field}'"
                    )

    # Some artifacts hand the token out from a status/session endpoint and
    # rotate it per request, so pick it up wherever it appears.
    if isinstance(payload, dict):
        for key in ("csrf", "csrfToken", "csrf_token"):
            fresh = payload.get(key)
            if isinstance(fresh, str) and fresh:
                record["_csrf"] = fresh
                break

    if not record["ok"] and isinstance(payload, dict):
        record["response_message"] = str(payload.get("message") or payload)[:160]
    return record


def execute_flow(base_url: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Run the derived plan against a live server. This is what decides pass/fail."""
    variables: Dict[str, Any] = {
        k: v
        for k, v in (spec.get("variables") or {}).items()
        # A spec that could not determine a value sometimes emits "${x}" for x.
        # Keeping it would send the literal placeholder as real input.
        if not (isinstance(v, str) and v.strip() == "${" + k + "}")
    }
    csrf = spec.get("csrf") or None
    results: List[Dict[str, Any]] = []

    # Artifacts enforce same-origin on state-changing requests by checking the
    # Origin (and sometimes Referer) header, which a browser always sends and a
    # bare HTTP client does not. Without these, a correct CSRF defence rejects
    # every POST and a working artifact reads as broken.
    browser_headers = {"Origin": base_url, "Referer": base_url + "/"}

    with httpx.Client(
        verify=False,
        timeout=REQUEST_TIMEOUT_S,
        follow_redirects=True,
        headers=browser_headers,
    ) as client:
        landing = client.get(base_url + "/")
        csrf_value = None
        if csrf and csrf.get("html_regex"):
            try:
                found = re.search(csrf["html_regex"], landing.text)
                csrf_value = found.group(1) if found else None
            except re.error:
                csrf_value = None
        # Values generated per boot and rendered into the page (pre-filled
        # recovery references, displayed demo codes) cannot be known ahead of
        # time; pull them out of the landing HTML.
        for name, pattern in (spec.get("html_variables") or {}).items():
            try:
                found = re.search(pattern, landing.text)
            except re.error:
                continue
            if found and found.groups():
                variables[name] = found.group(1)

        if csrf_value:
            # Expose it so a step written as {"csrf": "${csrf}"} resolves to the
            # live token, while a forged literal in a negative step survives.
            variables.setdefault("csrf", csrf_value)
            variables.setdefault(csrf.get("field", "csrf"), csrf_value)

        for step in (spec.get("steps") or []) + [
            {**s, "expect_failure": True} for s in (spec.get("negative_steps") or [])
        ]:
            record = _run_step(client, base_url, step, variables, csrf, csrf_value)
            refreshed = record.pop("_csrf", None)
            if refreshed:
                csrf_value = refreshed
                variables["csrf"] = refreshed
            results.append(record)

    positives = [r for r in results if not r["expect_failure"]]
    negatives = [r for r in results if r["expect_failure"]]
    # "ok" reflects the functional claim only: does the recovery journey work?
    # Negative checks are reported alongside but do not veto it — they are
    # model-authored and can be badly chosen (e.g. asserting rejection on a
    # route that deliberately returns a generic response to avoid account
    # enumeration, where a uniform reply is correct behaviour, not a defect).
    return {
        "ok": bool(positives) and all(r["ok"] for r in positives),
        "landing_status": landing.status_code,
        "csrf_found": bool(csrf_value),
        "steps_total": len(results),
        "steps_passed": sum(1 for r in results if r["ok"]),
        "happy_path_passed": sum(1 for r in positives if r["ok"]),
        "happy_path_total": len(positives),
        "negative_passed": sum(1 for r in negatives if r["ok"]),
        "negative_total": len(negatives),
        # When the happy path is broken every request fails, so negative checks
        # "pass" for the wrong reason. Flag that so they are not read as evidence
        # of correct rejection behaviour.
        "negatives_meaningful": bool(positives) and all(r["ok"] for r in positives),
        "steps": results,
    }


def flow_test(
    run_dir: str,
    llm,
    certs_src: Optional[str] = None,
    reuse_spec: bool = True,
) -> Dict[str, Any]:
    """
    Derive a test plan for run_dir/app.ts, boot it, and execute the plan.

    Reuses smoke_test's boot/port-discovery/locking so a live server is never
    started twice or raced against a sibling run. Writes flow_spec.json (the
    derived plan, for audit) and flow.json (the result).
    """
    run_path = pathlib.Path(run_dir)
    app_path = run_path / "app.ts"
    spec_path = run_path / "flow_spec.json"
    out_path = run_path / "flow.json"

    if not app_path.is_file():
        result = {"ok": False, "stage": "missing_artifact", "error": "app.ts not found"}
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    source = app_path.read_text(encoding="utf-8", errors="replace")

    spec = None
    if reuse_spec and spec_path.is_file():
        try:
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except Exception:
            spec = None
    if spec is None:
        try:
            spec = derive_flow_spec(source, llm)
        except Exception as e:
            result = {
                "ok": False,
                "stage": "spec_derivation_failed",
                "error": f"{type(e).__name__}: {e}",
            }
            out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
            return result
        spec_path.write_text(
            json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    smoke = smoke_test(
        run_dir,
        certs_src=certs_src,
        on_ready=lambda base, ports: execute_flow(base, spec),
        write_result=False,  # smoke.json is written by the caller's own smoke run
    )

    if not smoke.get("ok"):
        result = {
            "ok": False,
            "stage": f"server_{smoke.get('stage')}",
            "error": smoke.get("error"),
        }
    else:
        result = smoke.get("on_ready_result") or {
            "ok": False,
            "stage": "no_result",
            "error": "flow did not execute",
        }
        result["stage"] = "executed"

    result["spec_steps"] = len(spec.get("steps") or []) + len(
        spec.get("negative_steps") or []
    )
    out_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result
