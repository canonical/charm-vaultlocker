# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Configure and manage the vaultlocker workload."""

import configparser
import io
import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

VAULT_KV_VERSION = "2"
CONFIG_PATH = Path("/var/snap/vaultlocker/common")


def write_vault_configuration(
    config_dir: Path,
    vault_url: str,
    ca_certificate: str,
    mount: str,
    role_id: str,
    role_secret_id: str,
) -> Path:
    """Write a unit's vault configuration and return its file path."""
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_dir.chmod(0o700)

    ca_path = config_dir / "vault-ca.pem"
    config_path = config_dir / "vaultlocker.conf"
    values = {
        "url": vault_url,
        "approle": role_id,
        "secret_id": role_secret_id,
        "backend": mount,
        "kv_version": VAULT_KV_VERSION,
        "ca_bundle": str(ca_path),
    }

    config = configparser.ConfigParser()
    # vaultlocker's parser uses % interpolation, preserve literal % characters.
    config["vault"] = {key: value.replace("%", "%%") for key, value in values.items()}
    content = io.StringIO()
    config.write(content)

    _write_file(ca_path, ca_certificate)
    _write_file(config_path, content.getvalue())
    return config_path


def _write_file(path: Path, content: str) -> None:
    """Replace a file with complete contents and owner-only permissions."""
    # create a temporary file, then replace the destination atomically
    fd, temporary_name = tempfile.mkstemp(dir=path.parent)
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            os.fchmod(temp_file.fileno(), 0o600)
            temp_file.write(content)

        # Replace the destination only after writing and closing the file.
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
