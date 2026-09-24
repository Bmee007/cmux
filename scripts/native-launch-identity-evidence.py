#!/usr/bin/env python3
"""Native launch-identity evidence probe.

Runs against a live cmux app over the v2 Unix-socket protocol and checks the
launch-identity contract published through ``surface.create`` /
``surface.split`` / ``surface.launch_identity``.

Every check is behavioural: it creates real surfaces with real initial commands
and cross-checks reported identities against the live process table. It never
reads source text or metadata. Each case is isolated, so one failure never hides
the others. It prints a JSON report and exits non-zero if any hard case fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

_TESTS_V2 = Path(__file__).resolve().parent.parent / "tests_v2"
sys.path.insert(0, str(_TESTS_V2))

import cmux  # type: ignore[import-not-found]  # repo-local v2 client

MARKER_COMMAND = "sleep 600"
SCHEMA = "illumi.cmux-launch-identity.v1"
REPORT_PATH = os.environ.get("CMUX_LAUNCH_IDENTITY_REPORT", "native-launch-identity-report.json")
SOCKET_WAIT_SECONDS = float(os.environ.get("CMUX_SOCKET_WAIT_SECONDS", "60"))


@dataclass(frozen=True)
class CaseResult:
    name: str
    status: str
    detail: str
    observed: Optional[Any] = None


@dataclass
class Probe:
    client: cmux.cmux
    results: list[CaseResult] = field(default_factory=list)

    def record(self, name: str, status: str, detail: str, observed: Optional[Any] = None) -> None:
        self.results.append(CaseResult(name, status, detail, observed))

    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return dict(self.client._call(method, params) or {})

    def try_call(self, method: str, params: dict[str, Any]) -> tuple[bool, Any]:
        try:
            return True, self.call(method, params)
        except cmux.cmuxError as exc:
            return False, str(exc)

    def case(self, name: str, fn: Callable[[], tuple[str, str, Optional[Any]]]) -> None:
        try:
            status, detail, observed = fn()
        except Exception as exc:
            status, detail, observed = "fail", f"unexpected: {exc!r}", None
        self.record(name, status, detail, observed)

    @staticmethod
    def process_table(pid: int) -> tuple[Optional[int], Optional[int], Optional[str]]:
        try:
            out = subprocess.run(
                ["ps", "-o", "pid=,pgid=,command=", "-p", str(pid)],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        except OSError:
            return (None, None, None)
        parts = out.split(None, 2) if out else []
        if len(parts) < 3:
            return (None, None, None)
        try:
            return (int(parts[0]), int(parts[1]), parts[2])
        except ValueError:
            return (None, None, None)


def identity_problems(payload: Any, surface_id: str) -> list[str]:
    if not isinstance(payload, dict):
        return ["launch_identity missing"]
    problems: list[str] = []
    if payload.get("schema") != SCHEMA:
        problems.append(f"schema={payload.get('schema')!r}")
    if payload.get("valid") is not True:
        problems.append(f"valid={payload.get('valid')!r}")
    if str(payload.get("surface_id")) != surface_id:
        problems.append(f"surface_id={payload.get('surface_id')!r}")
    if payload.get("command") != MARKER_COMMAND:
        problems.append(f"command={payload.get('command')!r}")
    for key in ("pid", "pgid"):
        value = payload.get(key)
        if not isinstance(value, int) or value <= 0:
            problems.append(f"{key}={value!r}")
    token = payload.get("start_token")
    if not (isinstance(token, str) and token.isdigit() and int(token) > 0):
        problems.append(f"start_token={token!r}")
    return problems


def run_probe(client: cmux.cmux) -> Probe:
    probe = Probe(client)
    created: dict[str, Any] = {}

    def create_require_initial_command() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call(
            "surface.create",
            {"initial_command": MARKER_COMMAND, "require_launch_identity": True},
        )
        if not ok:
            return "fail", f"surface.create rejected: {out}", None
        surface_id = str(out.get("surface_id") or "")
        created["require_surface"] = surface_id
        identity = out.get("launch_identity")
        created["identity"] = identity
        problems = identity_problems(identity, surface_id)
        return ("pass" if not problems else "fail", "; ".join(problems) or "well-formed", identity)

    def cross_check_live_process() -> tuple[str, str, Optional[Any]]:
        identity = created.get("identity")
        if not isinstance(identity, dict) or not isinstance(identity.get("pid"), int):
            return "not_probed", "no identity from the require case to cross-check", None
        pid, pgid = int(identity["pid"]), int(identity["pgid"])
        real_pid, real_pgid, real_cmd = probe.process_table(pid)
        if real_pid is None:
            return "fail", f"pid {pid} not found in ps", None
        problems: list[str] = []
        if real_pid != pid:
            problems.append(f"ps pid {real_pid} != {pid}")
        if real_pgid != pgid:
            problems.append(f"ps pgid {real_pgid} != {pgid}")
        if not real_cmd or MARKER_COMMAND not in real_cmd:
            problems.append(f"ps command {real_cmd!r} lacks {MARKER_COMMAND!r}")
        return (
            "pass" if not problems else "fail",
            "; ".join(problems) or "matches live process",
            {"ps_pid": real_pid, "ps_pgid": real_pgid, "ps_command": real_cmd},
        )

    def plain_surface_identity() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call("surface.create", {})
        if not ok:
            return "fail", f"surface.create failed: {out}", None
        surface_id = str(out.get("surface_id") or "")
        created["plain_surface"] = surface_id
        ok_q, out_q = probe.try_call(
            "surface.launch_identity", {"surface_id": surface_id, "command": MARKER_COMMAND}
        )
        if ok_q:
            return "pass", "identity published for a plain surface", out_q.get("launch_identity")
        return "fail", f"no identity for a plain surface: {out_q}", None

    def initial_command_without_require() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call("surface.create", {"initial_command": MARKER_COMMAND})
        if not ok:
            return "fail", f"surface.create failed: {out}", None
        surface_id = str(out.get("surface_id") or "")
        created["no_require_surface"] = surface_id
        embedded = out.get("launch_identity")
        ok_q, out_q = probe.try_call(
            "surface.launch_identity", {"surface_id": surface_id, "command": MARKER_COMMAND}
        )
        observed = {"embedded": embedded, "queried": out_q.get("launch_identity") if ok_q else None}
        if ok_q or isinstance(embedded, dict):
            return "pass", "identity present without require_launch_identity", observed
        return "fail", f"no identity without require: {out_q}", observed

    def require_without_command() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call("surface.create", {"require_launch_identity": True})
        return ("pass", f"rejected: {out}", None) if not ok else ("fail", "call unexpectedly succeeded", out)

    def require_non_normalized() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call(
            "surface.create",
            {"initial_command": f" {MARKER_COMMAND} ", "require_launch_identity": True},
        )
        return ("pass", f"rejected: {out}", None) if not ok else ("fail", "call unexpectedly succeeded", out)

    def split_require_without_command() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call("surface.split", {"direction": "right", "require_launch_identity": True})
        return ("pass", f"rejected: {out}", None) if not ok else ("fail", "call unexpectedly succeeded", out)

    def unknown_surface() -> tuple[str, str, Optional[Any]]:
        ok, out = probe.try_call(
            "surface.launch_identity",
            {"surface_id": "00000000-0000-0000-0000-000000000000"},
        )
        return ("pass", f"rejected: {out}", None) if not ok else ("fail", "call unexpectedly succeeded", out)

    def closed_surface() -> tuple[str, str, Optional[Any]]:
        surface_id = created.get("plain_surface") or created.get("require_surface")
        if not surface_id:
            return "not_probed", "no surface available to close", None
        probe.try_call("surface.close", {"surface_id": surface_id})
        time.sleep(0.3)
        ok, out = probe.try_call("surface.launch_identity", {"surface_id": surface_id})
        return ("pass", f"rejected: {out}", None) if not ok else ("fail", "call unexpectedly succeeded", out)

    probe.case("create_requires_launch_identity", create_require_initial_command)
    probe.case("identity_matches_live_process", cross_check_live_process)
    probe.case("plain_surface_publishes_identity", plain_surface_identity)
    probe.case("initial_command_without_require", initial_command_without_require)
    probe.case("require_without_initial_command", require_without_command)
    probe.case("require_non_normalized_command", require_non_normalized)
    probe.case("split_require_without_command", split_require_without_command)
    probe.case("unknown_surface_not_found", unknown_surface)
    probe.case("closed_surface_not_found", closed_surface)
    probe.record(
        "no_send_text_on_launch_path",
        "not_probed",
        "initial_command is passed to addWorkspace(initialTerminalCommand:) with no surface.send_text; "
        "a runtime proof needs instrumented debug logging",
    )
    probe.record(
        "stale_token_and_reused_identity",
        "not_probed",
        "requires a PID-reuse harness; the consumer (IllumiZ) validates pid/pgid/start_token",
    )
    return probe


def _resolve_socket() -> str:
    explicit = os.environ.get("CMUX_SOCKET_PATH")
    if explicit:
        return explicit
    for marker in (
        os.path.expanduser("~/Library/Application Support/cmux/last-socket-path"),
        "/tmp/cmux-last-socket-path",
    ):
        try:
            value = Path(marker).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return "/tmp/cmux-debug.sock"


def main() -> int:
    socket_path = _resolve_socket()
    deadline = time.time() + SOCKET_WAIT_SECONDS
    while not os.path.exists(socket_path) and time.time() < deadline:
        time.sleep(0.5)

    client = cmux.cmux(socket_path)
    client.connect()
    try:
        probe = run_probe(client)
    finally:
        client.close()

    report = {
        "socket_path": socket_path,
        "marker_command": MARKER_COMMAND,
        "passed": sum(1 for r in probe.results if r.status == "pass"),
        "failed": probe.fail_count(),
        "not_probed": sum(1 for r in probe.results if r.status == "not_probed"),
        "results": [
            {"name": r.name, "status": r.status, "detail": r.detail, "observed": r.observed}
            for r in probe.results
        ],
    }
    Path(REPORT_PATH).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if probe.fail_count() else 0


if __name__ == "__main__":
    raise SystemExit(main())
