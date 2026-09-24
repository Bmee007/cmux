#!/usr/bin/env python3
"""Native launch-identity evidence probe.

Runs against a live cmux app over the v2 Unix-socket protocol and checks the
launch-identity contract that the native (ghostty) fork-owner capture publishes
through ``surface.create`` / ``surface.split`` / ``surface.launch_identity``.

Every check is behavioural: it creates real surfaces with real initial commands
and cross-checks the reported identity against the live process table. It never
reads source text or metadata.

The probe prints a JSON report and exits non-zero if any hard check fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_TESTS_V2 = Path(__file__).resolve().parent.parent / "tests_v2"
sys.path.insert(0, str(_TESTS_V2))

import cmux  # type: ignore[import-not-found]  # repo-local v2 client

MARKER_COMMAND = "sleep 600"
SCHEMA = "illumi.cmux-launch-identity.v1"
REPORT_PATH = os.environ.get(
    "CMUX_LAUNCH_IDENTITY_REPORT", "native-launch-identity-report.json"
)
SOCKET_WAIT_SECONDS = float(os.environ.get("CMUX_SOCKET_WAIT_SECONDS", "60"))


@dataclass(frozen=True)
class CaseResult:
    name: str
    status: str  # "pass" | "fail" | "not_probed"
    detail: str
    observed: Optional[Any] = None


@dataclass
class Probe:
    client: cmux.cmux
    results: list[CaseResult] = field(default_factory=list)

    # -- bookkeeping -------------------------------------------------------
    def record(
        self, name: str, status: str, detail: str, observed: Optional[Any] = None
    ) -> None:
        self.results.append(CaseResult(name, status, detail, observed))

    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "fail")

    # -- helpers -----------------------------------------------------------
    def ok_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        result = self.client._call(method, params)
        return dict(result or {})

    def expect_error(self, method: str, params: dict[str, Any], code: str) -> tuple[bool, str]:
        """Return (matched, observed_message)."""
        try:
            self.client._call(method, params)
        except cmux.cmuxError as exc:
            message = str(exc)
            return (message.startswith(f"{code}:") or code in message, message)
        return (False, "call unexpectedly succeeded")

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
        if not out:
            return (None, None, None)
        parts = out.split(None, 2)
        if len(parts) < 3:
            return (None, None, None)
        try:
            return (int(parts[0]), int(parts[1]), parts[2])
        except ValueError:
            return (None, None, None)


def _identity_is_well_formed(payload: dict[str, Any], surface_id: str) -> tuple[bool, str]:
    if payload.get("schema") != SCHEMA:
        return (False, f"schema={payload.get('schema')!r} != {SCHEMA!r}")
    if payload.get("valid") is not True:
        return (False, f"valid={payload.get('valid')!r}")
    if str(payload.get("surface_id")) != surface_id:
        return (False, f"surface_id={payload.get('surface_id')!r} != {surface_id!r}")
    if payload.get("command") != MARKER_COMMAND:
        return (False, f"command={payload.get('command')!r} != {MARKER_COMMAND!r}")
    for key in ("pid", "pgid"):
        value = payload.get(key)
        if not isinstance(value, int) or value <= 0:
            return (False, f"{key}={value!r} is not a positive int")
    token = payload.get("start_token")
    if not (isinstance(token, str) and token.isdigit() and int(token) > 0):
        return (False, f"start_token={token!r} is not a positive int string")
    return (True, "well-formed")


def run_probe(client: cmux.cmux) -> Probe:
    probe = Probe(client)

    # 1. Happy path: require_launch_identity on surface.create.
    created: dict[str, Any] = {}
    try:
        created = probe.ok_call(
            "surface.create",
            {"initial_command": MARKER_COMMAND, "require_launch_identity": True},
        )
    except cmux.cmuxError as exc:
        probe.record("create_requires_launch_identity", "fail", f"call failed: {exc}")
        return probe

    surface_id = str(created.get("surface_id") or "")
    identity = created.get("launch_identity")
    if not isinstance(identity, dict):
        probe.record(
            "create_requires_launch_identity",
            "fail",
            "surface.create returned no launch_identity",
            created,
        )
        return probe
    kind, why = _identity_is_well_formed(identity, surface_id)
    probe.record(
        "create_requires_launch_identity",
        "pass" if kind else "fail",
        why,
        identity,
    )
    if not kind:
        return probe

    # 2. Cross-check the identity against the real process table.
    pid = int(identity["pid"])
    pgid = int(identity["pgid"])
    real_pid, real_pgid, real_cmd = probe.process_table(pid)
    if real_pid is None:
        probe.record("identity_matches_live_process", "fail", f"pid {pid} not in ps")
    else:
        problems: list[str] = []
        if real_pid != pid:
            problems.append(f"ps pid {real_pid} != {pid}")
        if real_pgid != pgid:
            problems.append(f"ps pgid {real_pgid} != {pgid}")
        if not real_cmd or MARKER_COMMAND not in real_cmd:
            problems.append(f"ps command {real_cmd!r} lacks {MARKER_COMMAND!r}")
        probe.record(
            "identity_matches_live_process",
            "pass" if not problems else "fail",
            "; ".join(problems) or f"pid={pid} pgid={pgid} cmd={real_cmd!r}",
            {"ps_pid": real_pid, "ps_pgid": real_pgid, "ps_command": real_cmd},
        )

    # 3. surface.launch_identity returns the same identity for that surface.
    try:
        fetched = probe.ok_call(
            "surface.launch_identity",
            {"surface_id": surface_id, "command": MARKER_COMMAND},
        ).get("launch_identity")
    except cmux.cmuxError as exc:
        fetched = None
        probe.record("launch_identity_lookup", "fail", f"call failed: {exc}")
    else:
        same = isinstance(fetched, dict) and fetched.get("pid") == pid and fetched.get(
            "start_token"
        ) == identity.get("start_token")
        probe.record(
            "launch_identity_lookup",
            "pass" if same else "fail",
            "same pid/start_token as create-time identity" if same else "identity drifted",
            fetched,
        )

    # 4. require_launch_identity without initial_command must fail closed.
    matched, observed = probe.expect_error(
        "surface.create", {"require_launch_identity": True}, "invalid_params"
    )
    probe.record("require_without_initial_command", "pass" if matched else "fail", observed)

    # 5. Non-normalized initial_command must fail closed.
    matched, observed = probe.expect_error(
        "surface.create",
        {"initial_command": f" {MARKER_COMMAND} ", "require_launch_identity": True},
        "invalid_params",
    )
    probe.record("require_non_normalized_command", "pass" if matched else "fail", observed)

    # 6. surface.split honours the same fail-closed rule.
    matched, observed = probe.expect_error(
        "surface.split", {"direction": "right", "require_launch_identity": True}, "invalid_params"
    )
    probe.record("split_require_without_command", "pass" if matched else "fail", observed)

    # 7. A surface that was not launched with an exact command has no identity.
    plain = probe.ok_call("surface.create", {})
    plain_id = str(plain.get("surface_id") or "")
    if plain_id:
        matched, observed = probe.expect_error(
            "surface.launch_identity",
            {"surface_id": plain_id},
            "launch_identity_unavailable",
        )
        probe.record(
            "identity_unavailable_without_command",
            "pass" if matched else "fail",
            observed,
        )
        probe.client._call("surface.close", {"surface_id": plain_id})

    # 8. Unknown surface id must fail closed.
    matched, observed = probe.expect_error(
        "surface.launch_identity",
        {"surface_id": "00000000-0000-0000-0000-000000000000"},
        "not_found",
    )
    probe.record("unknown_surface_not_found", "pass" if matched else "fail", observed)

    # 9. A closed surface must not resolve.
    probe.client._call("surface.close", {"surface_id": surface_id})
    time.sleep(0.3)
    matched, observed = probe.expect_error(
        "surface.launch_identity", {"surface_id": surface_id}, "not_found"
    )
    probe.record("closed_surface_not_found", "pass" if matched else "fail", observed)

    # Recorded, not asserted: these need the consumer or process-reuse harness.
    probe.record(
        "no_send_text_on_launch_path",
        "not_probed",
        "initial_command is passed to addWorkspace(initialCommand:) with no surface.send_text; "
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
            {
                "name": r.name,
                "status": r.status,
                "detail": r.detail,
                "observed": r.observed,
            }
            for r in probe.results
        ],
    }
    Path(REPORT_PATH).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if probe.fail_count() else 0


if __name__ == "__main__":
    raise SystemExit(main())
