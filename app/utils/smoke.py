"""
Smoke test for a generated app.ts.

PASS_MARKER only records that the Evaluator LLM judged the code complete — it
never executes anything. This module actually boots the artifact under Bun and
checks that it serves a response, which:

  * catches artifacts that pass review but crash on startup, and
  * yields a reportable statistic (how often LLM-judged-complete code runs).

Ports are not predictable: generated apps variously hardcode 8441/8443, read
process.env.PORT, or pick something else. We therefore set PORT as a hint, then
detect the real port from the server's own startup log, falling back to scanning
the source.
"""

import contextlib
import fcntl
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional

import httpx

BOOT_TIMEOUT_S = 30.0
PROBE_TIMEOUT_S = 10.0
POLL_INTERVAL_S = 0.25
LOCK_TIMEOUT_S = 900.0

# Generated apps frequently hardcode a port (443, 80, 8441, 8443 have all been
# observed), so two smoke tests running at once would fight over the same
# socket: one fails to bind, and the other may answer a probe meant for its
# neighbour. Generation stays parallel; only this short boot-and-probe step is
# serialised across processes.
DEFAULT_LOCK_PATH = pathlib.Path(tempfile.gettempdir()) / "llm_auth_smoke_test.lock"

_URL_PORT = re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::\]):(\d+)")
_ANY_PORT = re.compile(r"\bport\b\D{0,12}?(\d{2,5})", re.IGNORECASE)
_SRC_PORT = re.compile(r"port\s*:\s*(\d{2,5})")
# const HTTPS_PORT = Number(process.env.HTTPS_PORT || 3000)  /  const p = 8443
_SRC_CONST_PORT = re.compile(
    r"(?:const|let|var)\s+\w*(?:PORT|Port|port)\w*\s*=[^;\n]*?(\d{2,5})"
)
_EADDRINUSE = re.compile(r"EADDRINUSE|address already in use|port \d+ in use", re.IGNORECASE)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _listening_ports_for_pid(pid: int) -> List[int]:
    """
    Ask the OS which TCP ports this process is listening on.

    This is the authoritative answer and the primary detection method. Guessing
    from source or logs is unreliable: generated apps declare ports through
    variables (`port: HTTPS_PORT`), read non-standard env names, and often log
    nothing at all on startup.
    """
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return []

    ports = set()
    for line in out.stdout.splitlines()[1:]:
        match = re.search(r":(\d+)\s+\(LISTEN\)", line)
        if match:
            ports.add(int(match.group(1)))
    return sorted(ports)


def _candidate_ports(stream_text: str, source: str, hint: int) -> List[int]:
    """
    Fallback port guesses, used only when the OS query is unavailable: ports the
    server logged, then literals in the source, then the ports we suggested.
    """
    found = []
    for pattern in (_URL_PORT, _ANY_PORT):
        for match in pattern.finditer(stream_text):
            found.append(int(match.group(1)))
    for pattern in (_SRC_PORT, _SRC_CONST_PORT):
        for match in pattern.finditer(source):
            found.append(int(match.group(1)))
    found.append(hint)

    ordered = []
    for port in found:
        if 1 <= port <= 65535 and port not in ordered:
            ordered.append(port)
    return ordered


def _port_open(port: int, timeout: float = 0.3) -> bool:
    """Cheap liveness check — far faster than a full HTTP request while polling."""
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex(("127.0.0.1", port)) == 0


@contextlib.contextmanager
def _exclusive(lock_path: pathlib.Path, timeout_s: float = LOCK_TIMEOUT_S):
    """Serialise boot-and-probe across processes so hardcoded ports cannot clash."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "w")
    deadline = time.time() + timeout_s
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() > deadline:
                    raise TimeoutError(
                        f"timed out after {timeout_s:.0f}s waiting for {lock_path}"
                    )
                time.sleep(0.25)
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def _ensure_certs(run_dir: pathlib.Path, certs_src: Optional[pathlib.Path]) -> bool:
    """Generated apps read certs/{cert,key}.pem relative to cwd."""
    dest = run_dir / "certs"
    if (dest / "cert.pem").is_file() and (dest / "key.pem").is_file():
        return True
    if not certs_src or not certs_src.is_dir():
        return False
    dest.mkdir(exist_ok=True)
    ok = False
    for name in ("cert.pem", "key.pem"):
        src = certs_src / name
        if src.is_file():
            shutil.copy2(src, dest / name)
            ok = True
    return ok


def _probe(ports: List[int]) -> Dict[str, Any]:
    """
    Probe each port, HTTPS first (apps are meant to enforce TLS), then plain
    HTTP. An app may listen on several ports (e.g. 3000 TLS + 3001 redirect);
    the first that answers wins.
    """
    errors = []
    for port in ports:
        for scheme in ("https", "http"):
            url = f"{scheme}://127.0.0.1:{port}/"
            try:
                with httpx.Client(verify=False, timeout=PROBE_TIMEOUT_S) as client:
                    resp = client.get(url, follow_redirects=True)
            except Exception as e:  # connection refused, TLS mismatch, ...
                errors.append(f"{scheme}://:{port}: {type(e).__name__}")
                continue
            if resp.status_code < 500:
                return {
                    "ok": True,
                    "url": url,
                    "port": port,
                    "scheme": scheme,
                    "status_code": resp.status_code,
                    "body_bytes": len(resp.content),
                    "error": None,
                }
            errors.append(f"{scheme}://:{port}: HTTP {resp.status_code}")
    return {
        "ok": False,
        "url": None,
        "port": ports[0] if ports else None,
        "scheme": None,
        "status_code": None,
        "body_bytes": 0,
        "error": "; ".join(errors) or "no ports to probe",
    }


def smoke_test(
    run_dir: str,
    certs_src: Optional[str] = None,
    boot_timeout_s: float = BOOT_TIMEOUT_S,
    lock_path: Optional[pathlib.Path] = None,
) -> Dict[str, Any]:
    """
    Boot run_dir/app.ts under Bun and verify it serves. Always tears the
    process down. Writes run_dir/smoke.json and returns the same dict.
    """
    run_path = pathlib.Path(run_dir)
    app_path = run_path / "app.ts"
    started = time.time()

    result: Dict[str, Any] = {
        "ok": False,
        "stage": "init",
        "port": None,
        "status_code": None,
        "boot_seconds": None,
        "error": None,
        "stdout_tail": "",
        "stderr_tail": "",
    }

    if not app_path.is_file():
        result.update(stage="missing_artifact", error="app.ts not found")
        _write(run_path, result)
        return result

    if shutil.which("bun") is None:
        result.update(stage="no_bun", error="bun executable not on PATH")
        _write(run_path, result)
        return result

    source = app_path.read_text(encoding="utf-8", errors="replace")
    result["certs_available"] = _ensure_certs(
        run_path, pathlib.Path(certs_src) if certs_src else None
    )

    # Offer free ports under every env name these apps have been seen to read,
    # so an artifact that honours env config avoids colliding with whatever the
    # host already runs (Docker on 8080 has been observed).
    hint_port = _free_port()
    env = {
        **os.environ,
        "PORT": str(hint_port),
        "HTTPS_PORT": str(hint_port),
        "HTTP_PORT": str(_free_port()),
        "NODE_ENV": "production",
    }

    out_path = run_path / "smoke_stdout.log"
    proc = None
    try:
        with _exclusive(lock_path or DEFAULT_LOCK_PATH), open(
            out_path, "w+", encoding="utf-8"
        ) as out_f:
            # Any candidate port already listening before we start belongs to
            # something else. Probing it would report a neighbour's app (or an
            # unrelated local service) as this artifact's success.
            occupied_before = [
                p for p in _candidate_ports("", source, hint_port) if _port_open(p)
            ]
            result["occupied_before"] = occupied_before
            proc = subprocess.Popen(
                ["bun", "app.ts"],
                cwd=str(run_path),
                env=env,
                stdout=out_f,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group, so teardown is complete
            )

            result["stage"] = "booting"
            live_ports: List[int] = []
            deadline = time.time() + boot_timeout_s

            # Poll until the process is listening. The OS is asked directly
            # which ports it opened; source/log guesses are only a fallback.
            while time.time() < deadline:
                if proc.poll() is not None:
                    logged = pathlib.Path(out_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                    conflict = bool(_EADDRINUSE.search(logged))
                    result.update(
                        stage="port_conflict" if conflict else "exited_early",
                        error=(
                            "port already in use on this host — environment "
                            "conflict, not necessarily a defect in the artifact"
                            if conflict
                            else f"process exited with code {proc.returncode} during boot"
                        ),
                    )
                    break

                live_ports = _listening_ports_for_pid(proc.pid)
                if live_ports:
                    result["port_source"] = "os"
                    break

                out_f.flush()
                logged = pathlib.Path(out_path).read_text(
                    encoding="utf-8", errors="replace"
                )
                guesses = [
                    p
                    for p in _candidate_ports(logged, source, hint_port)
                    if p not in occupied_before and _port_open(p)
                ]
                if guesses:
                    live_ports = guesses
                    result["port_source"] = "guess"
                    break
                time.sleep(POLL_INTERVAL_S)

            if result["stage"] == "booting":
                if not live_ports:
                    result.update(
                        stage="never_listened",
                        error=f"process opened no listening port within {boot_timeout_s:.0f}s",
                    )
                else:
                    result["listening_ports"] = live_ports
                    result["stage"] = "probing"
                    probe = _probe(live_ports)
                    result.update(
                        ok=probe["ok"],
                        port=probe["port"],
                        status_code=probe["status_code"],
                        url=probe["url"],
                        scheme=probe["scheme"],
                        error=probe["error"],
                        stage="served" if probe["ok"] else "no_response",
                    )
    except Exception as e:
        result.update(stage="exception", error=f"{type(e).__name__}: {e}")
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()

    result["boot_seconds"] = round(time.time() - started, 2)
    if out_path.is_file():
        log_text = out_path.read_text(encoding="utf-8", errors="replace")
        result["stdout_tail"] = log_text[-2000:]

    _write(run_path, result)
    return result


def _write(run_path: pathlib.Path, result: Dict[str, Any]) -> None:
    (run_path / "smoke.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
