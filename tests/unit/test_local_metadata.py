# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for local device state storage."""

import logging
import stat

import pytest

from local_metadata import (
    REQUEST_TYPE_ENCRYPT,
    REQUEST_TYPE_ENROLL,
    DeviceState,
    LocalMetadataStore,
)

TARGET = "/dev/disk/by-id/device-a"
OTHER_TARGET = "/dev/disk/by-id/device-b"


@pytest.fixture
def store(tmp_path):
    """Create a store backed by a temporary state file."""
    return LocalMetadataStore(tmp_path / "state.json")


def test_empty_store_has_no_state(store):
    assert store.get(TARGET) is None
    assert store.all() == {}


def test_set_and_get_state(store):
    expected = DeviceState(request_type=REQUEST_TYPE_ENROLL)

    store.set(TARGET, expected)

    assert store.get(TARGET) == expected


def test_state_persists_across_store_instances(store):
    expected = DeviceState(
        request_type=REQUEST_TYPE_ENCRYPT,
        completed=True,
        luks_uuid="uuid-1",
        mapper_path="/dev/mapper/crypt-uuid-1",
    )

    store.set(TARGET, expected)

    new_store = LocalMetadataStore(store.path)

    assert new_store.get(TARGET) == expected


def test_record_failure_saves_failure(store):
    state = store.record_failure(
        TARGET,
        REQUEST_TYPE_ENROLL,
        "Vault cluster identity mismatch",
    )

    assert state.request_type == REQUEST_TYPE_ENROLL
    assert state.completed is False
    assert state.last_failure is not None
    assert state.last_failure.message == "Vault cluster identity mismatch"
    assert state.last_failure.timestamp
    assert store.get(TARGET) == state


def test_mark_completed_saves_result_and_clears_failure(store):
    store.record_failure(
        TARGET,
        REQUEST_TYPE_ENROLL,
        "Failed to enroll device",
    )

    state = store.mark_completed(
        TARGET,
        REQUEST_TYPE_ENROLL,
        "uuid-1",
        "/dev/mapper/crypt-uuid-1",
    )

    assert state == DeviceState(
        request_type=REQUEST_TYPE_ENROLL,
        completed=True,
        luks_uuid="uuid-1",
        mapper_path="/dev/mapper/crypt-uuid-1",
    )
    assert store.get(TARGET) == state


def test_multiple_devices_are_preserved(store):
    first = DeviceState(request_type=REQUEST_TYPE_ENROLL)
    second = DeviceState(
        request_type=REQUEST_TYPE_ENCRYPT,
        completed=True,
        luks_uuid="uuid-2",
        mapper_path="/dev/mapper/crypt-uuid-2",
    )

    store.set(TARGET, first)
    store.set(OTHER_TARGET, second)

    assert store.all() == {
        TARGET: first,
        OTHER_TARGET: second,
    }


def test_corrupt_state_file_is_ignored(tmp_path, caplog):
    path = tmp_path / "state.json"
    path.write_text("not-json", encoding="utf-8")
    store = LocalMetadataStore(path)

    with caplog.at_level(logging.WARNING):
        assert store.all() == {}

    assert "Unable to read vaultlocker state file" in caplog.text


def test_unreadable_state_file_is_ignored(tmp_path, monkeypatch, caplog):
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    store = LocalMetadataStore(path)

    def raise_oserror(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(type(path), "read_text", raise_oserror)

    with caplog.at_level(logging.WARNING):
        assert store.all() == {}

    assert "Unable to read vaultlocker state file" in caplog.text


def test_state_file_is_owner_only(store):
    store.set(
        TARGET,
        DeviceState(request_type=REQUEST_TYPE_ENCRYPT),
    )

    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
