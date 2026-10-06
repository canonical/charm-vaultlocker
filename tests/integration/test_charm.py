# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# The integration tests use the Jubilant library and the pytest-jubilant plugin.
# See https://canonical.com/juju/docs/ops/latest/howto/write-integration-tests-for-a-charm/

import json
import os
import time

import jubilant
import pytest

_PRINCIPAL_APP = "principal"
_VAULT_APP = "vault"
_VAULTLOCKER_APP = "vaultlocker"
_VAULT_CHANNEL = "2.0/stable"

# Run the CLI supplied by the Vault snap on the Vault unit.
_VAULT_CLI = "VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=1 /snap/bin/vault"


def _vault_command(
    juju: jubilant.Juju,
    unit: str,
    command: str,
    *,
    stdin: str | None = None,
    allow_sealed: bool = False,
) -> str:
    """Run a Vault command on its unit."""
    try:
        return juju.cli("ssh", unit, command, stdin=stdin)
    except jubilant.CLIError as error:
        # `vault status` exits with 2 while Vault is sealed, but still
        # returns its status as JSON.
        if allow_sealed and error.returncode == 2:
            return error.stdout
        raise RuntimeError(f"Vault command failed with exit code {error.returncode}") from None


def _wait_for_vault(juju: jubilant.Juju, unit: str, *, unsealed: bool = False) -> dict:
    """Wait for Vault to respond, then optionally wait for it to unseal."""
    deadline = time.monotonic() + (180 if unsealed else 1800)

    while True:
        try:
            output = _vault_command(
                juju,
                unit,
                f"{_VAULT_CLI} status -format=json",
                allow_sealed=True,
            )
            status = json.loads(output)
            if not unsealed or (
                status.get("initialized")
                and not status.get("sealed")
                and not status.get("standby")
            ):
                return status
        except (RuntimeError, json.JSONDecodeError):
            pass

        if time.monotonic() >= deadline:
            raise TimeoutError("Vault did not reach the expected state")
        time.sleep(5)


def _deploy_vault(juju: jubilant.Juju) -> None:
    """Deploy, initialize, unseal, and authorize machine Vault."""
    juju.deploy(_VAULT_APP, channel=_VAULT_CHANNEL, base="ubuntu@24.04")

    status = juju.wait(
        lambda status: (
            _VAULT_APP in status.apps
            and len(status.get_units(_VAULT_APP)) == 1
            and all(
                unit.juju_status.current == "idle"
                for unit in status.get_units(_VAULT_APP).values()
            )
        ),
        timeout=1800,
    )
    vault_unit = next(iter(status.get_units(_VAULT_APP)))

    vault_status = _wait_for_vault(juju, vault_unit)
    assert not vault_status["initialized"], "Use a fresh model for Vault setup"

    credentials = json.loads(
        _vault_command(
            juju,
            vault_unit,
            (f"{_VAULT_CLI} operator init -key-shares=1 -key-threshold=1 -format=json"),
        )
    )

    _vault_command(
        juju,
        vault_unit,
        f"{_VAULT_CLI} write -format=json sys/unseal -",
        stdin=json.dumps({"key": credentials["unseal_keys_b64"][0]}),
    )
    _wait_for_vault(juju, vault_unit, unsealed=True)

    token_output = _vault_command(
        juju,
        vault_unit,
        (
            "sh -c 'IFS= read -r VAULT_TOKEN; export VAULT_TOKEN; "
            f"{_VAULT_CLI} token create -ttl=10m -format=json'"
        ),
        stdin=credentials["root_token"] + "\n",
    )
    token = json.loads(token_output)["auth"]["client_token"]

    secret_uri = juju.add_secret("vaultlocker-it-vault-token", {"token": token})
    try:
        juju.grant_secret(secret_uri, _VAULT_APP)
        juju.run(
            f"{_VAULT_APP}/leader",
            "authorize-charm",
            {"secret-id": secret_uri.unique_identifier},
        )
    finally:
        juju.remove_secret(secret_uri)

    juju.wait(
        lambda status: jubilant.all_active(status, _VAULT_APP),
        timeout=1800,
    )


def _deploy_subordinate(juju: jubilant.Juju, charm, principal_charm) -> None:
    """Deploy the principal and Vaultlocker."""
    juju.deploy(principal_charm, app=_PRINCIPAL_APP)
    juju.wait(
        lambda status: (
            _PRINCIPAL_APP in status.apps and jubilant.all_active(status, _PRINCIPAL_APP)
        ),
        timeout=1800,
    )

    channel = os.environ.get("VAULTLOCKER_SNAP_CHANNEL")
    config = {"snap-channel": channel} if channel else None

    juju.deploy(charm, app=_VAULTLOCKER_APP, config=config)
    juju.integrate(
        f"{_PRINCIPAL_APP}:encrypted-device",
        f"{_VAULTLOCKER_APP}:encrypted-device",
    )


@pytest.mark.juju_setup
def test_subordinate_blocks_without_vault_kv(
    juju: jubilant.Juju,
    charm,
    principal_charm,
) -> None:
    """Vaultlocker is placed under the principal and blocks without vault-kv."""
    _deploy_vault(juju)
    _deploy_subordinate(juju, charm, principal_charm)

    status = juju.wait(
        lambda status: (
            _VAULTLOCKER_APP in status.apps
            and status.apps[_VAULTLOCKER_APP].app_status.current == "blocked"
            and len(status.get_units(_VAULTLOCKER_APP)) == 1
        ),
        timeout=1800,
    )
    principal_unit = next(iter(status.get_units(_PRINCIPAL_APP).values()))
    subordinate_unit = next(iter(status.get_units(_VAULTLOCKER_APP)))
    assert subordinate_unit in principal_unit.subordinates


def test_vault_kv_relation_becomes_active(juju: jubilant.Juju) -> None:
    """The direct vault-kv relation makes Vaultlocker active."""
    relations = juju.status().apps[_VAULTLOCKER_APP].relations
    if "vault-kv" not in relations:
        juju.integrate(
            f"{_VAULTLOCKER_APP}:vault-kv",
            f"{_VAULT_APP}:vault-kv",
        )

    juju.wait(jubilant.all_active, timeout=1800)
