# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the vaultlocker CLI wrapper."""

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import vaultlocker_cli

CONFIG_PATH = Path("/var/snap/vaultlocker/common/vaultlocker/vaultlocker.conf")
TARGET = "/dev/disk/by-id/device-a"


def completed(returncode=0, stdout=b"", stderr=b""):
    """Build a CompletedProcess-like object with bytes streams."""
    return subprocess.CompletedProcess(
        args=["vaultlocker"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_run_encrypt_success():
    stdout = json.dumps(
        {"luks_uuid": "a1b2c3d4", "mapper_path": "/dev/mapper/crypt-a1b2c3d4"}
    ).encode()

    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", return_value=completed(stdout=stdout)
    ) as run:
        result = vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    run.assert_called_once_with(
        ["vaultlocker", "--config", str(CONFIG_PATH), "encrypt", TARGET],
        input=None,
        capture_output=True,
        check=False,
    )
    assert result == vaultlocker_cli.VaultlockerResult(
        uuid="a1b2c3d4", mapper_path="/dev/mapper/crypt-a1b2c3d4"
    )


def test_run_enroll_passes_passphrase_on_stdin():
    stdout = json.dumps({"luks_uuid": "uuid", "mapper_path": "/dev/mapper/crypt-uuid"}).encode()

    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", return_value=completed(stdout=stdout)
    ) as run:
        result = vaultlocker_cli.run_enroll(TARGET, CONFIG_PATH, "s3cret")

    run.assert_called_once_with(
        ["vaultlocker", "--config", str(CONFIG_PATH), "enroll", TARGET],
        input=b"s3cret",
        capture_output=True,
        check=False,
    )
    assert result.uuid == "uuid"


def test_stdout_uses_last_json_line():
    stdout = (
        b"some log line\n"
        + json.dumps({"luks_uuid": "uuid", "mapper_path": "/dev/mapper/crypt-uuid"}).encode()
    )

    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", return_value=completed(stdout=stdout)
    ):
        result = vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert result.mapper_path == "/dev/mapper/crypt-uuid"


def test_missing_binary_reports_error():
    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", side_effect=OSError("no vaultlocker")
    ):
        with pytest.raises(vaultlocker_cli.VaultlockerCliError) as error:
            vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert "no vaultlocker" in str(error.value)


@pytest.mark.parametrize("returncode", [1, 3])
def test_tool_error_object_preserves_message(returncode):
    message = "Vault cluster identity mismatch: pinned cluster_id=old, observed cluster_id=new"
    stderr = json.dumps({"error": message}).encode()

    with mock.patch.object(
        vaultlocker_cli.subprocess,
        "run",
        return_value=completed(returncode=returncode, stderr=stderr),
    ):
        with pytest.raises(vaultlocker_cli.VaultlockerCliError) as error:
            vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert str(error.value) == message


def test_unstructured_failure_reports_missing_error_object():
    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", return_value=completed(returncode=2, stderr=b"boom")
    ):
        with pytest.raises(vaultlocker_cli.VaultlockerCliError) as error:
            vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert str(error.value) == "vaultlocker failed without a structured error"


def test_missing_result_fields_fail_closed():
    stdout = json.dumps({"luks_uuid": "uuid"}).encode()

    with mock.patch.object(
        vaultlocker_cli.subprocess, "run", return_value=completed(stdout=stdout)
    ):
        with pytest.raises(vaultlocker_cli.VaultlockerCliError) as error:
            vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert str(error.value) == "vaultlocker returned an unexpected result"


def test_empty_output_fails_closed():
    with mock.patch.object(vaultlocker_cli.subprocess, "run", return_value=completed(stdout=b"")):
        with pytest.raises(vaultlocker_cli.VaultlockerCliError) as error:
            vaultlocker_cli.run_encrypt(TARGET, CONFIG_PATH)

    assert str(error.value) == "vaultlocker returned an unexpected result"
