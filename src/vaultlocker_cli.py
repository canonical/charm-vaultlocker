# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Run vaultlocker commands and parse their JSON output."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

VAULTLOCKER_BINARY = "vaultlocker"


class VaultlockerCliError(Exception):
    """Error running a vaultlocker command."""


@dataclass
class VaultlockerResult:
    """A successful device provisioning result."""

    uuid: str
    mapper_path: str


def run_encrypt(target: str, config_path: Path) -> VaultlockerResult:
    """Encrypt a device using the vaultlocker snap."""
    return _run([VAULTLOCKER_BINARY, "--config", str(config_path), "encrypt", target])


def run_enroll(target: str, config_path: Path, passphrase: str) -> VaultlockerResult:
    """Add an existing LUKS device to be managed by vaultlocker."""
    return _run(
        [VAULTLOCKER_BINARY, "--config", str(config_path), "enroll", target],
        input_bytes=passphrase.encode("utf-8"),
    )


def _run(command: list[str], *, input_bytes: bytes | None = None) -> VaultlockerResult:
    """Run a vaultlocker command, translating its output into a result or error."""
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise VaultlockerCliError(f"Unable to run vaultlocker: {error}") from error

    if completed.returncode != 0:
        raise _error_from_stderr(completed.stderr)

    return _result_from_stdout(completed.stdout)


def _parse_json_object(payload: bytes) -> dict | None:
    """Parse the last non-empty line of ``payload`` as a JSON object."""
    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    try:
        data = json.loads(text.splitlines()[-1])
    except ValueError:
        return None

    return data if isinstance(data, dict) else None


def _result_from_stdout(stdout: bytes) -> VaultlockerResult:
    """Build a result from a successful vaultlocker invocation."""
    data = _parse_json_object(stdout)
    if not data or not data.get("luks_uuid") or not data.get("mapper_path"):
        raise VaultlockerCliError("vaultlocker returned an unexpected result")

    return VaultlockerResult(uuid=data["luks_uuid"], mapper_path=data["mapper_path"])


def _error_from_stderr(stderr: bytes) -> VaultlockerCliError:
    """Parse an error returned by vaultlocker."""
    data = _parse_json_object(stderr)
    if not data or not isinstance(data.get("error"), str) or not data["error"]:
        return VaultlockerCliError("vaultlocker failed without a structured error")

    return VaultlockerCliError(data["error"])
