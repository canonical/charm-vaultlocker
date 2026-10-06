# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# The integration tests use the Jubilant library and the pytest-jubilant plugin.
# See https://canonical.com/juju/docs/ops/latest/howto/write-integration-tests-for-a-charm/

import os
import pathlib
import subprocess

import pytest


@pytest.fixture(scope="session")
def charm():
    """Return the absolute path of the charm under test."""
    charm = os.environ.get("CHARM_PATH")
    if not charm:
        charm_dir = pathlib.Path()  # Assume the current working directory is the charm root.
        charms = list(charm_dir.glob("*.charm"))
        assert charms, f"No charms were found in {charm_dir.absolute()}"
        assert len(charms) == 1, f"Found more than one charm {charms}"
        charm = charms[0]
    path = pathlib.Path(charm).resolve()
    assert path.is_file(), f"{path} is not a file"
    return path


@pytest.fixture(scope="session")
def principal_charm():
    """Pack and return the encrypted-device principal test charm."""
    principal_dir = pathlib.Path(__file__).parent / "principal"
    subprocess.run(
        ["charmcraft", "pack"],
        cwd=principal_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    charms = list(principal_dir.glob("*.charm"))
    assert len(charms) == 1, f"Expected one principal charm, found {charms}"
    return charms[0].resolve()
