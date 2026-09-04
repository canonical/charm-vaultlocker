# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared fixtures for charm unit tests."""

import pytest
from ops import testing

import vaultlocker
from charm import VaultlockerCharm


@pytest.fixture
def ctx(monkeypatch, tmp_path) -> testing.Context:
    """Return a fresh charm context."""
    monkeypatch.setattr(vaultlocker, "CONFIG_PATH", tmp_path)

    return testing.Context(
        VaultlockerCharm,
        meta={
            "name": "vaultlocker",
            "requires": {
                "vault-kv": {
                    "interface": "vault-kv",
                    "limit": 1,
                },
            },
        },
    )
