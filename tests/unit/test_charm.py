# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://canonical.com/juju/docs/ops/latest/explanation/testing/

"""Unit tests for the Vaultlocker charm."""

import configparser
import json

from ops import testing

import vaultlocker
from charm import NONCE_SECRET_LABEL, VAULT_CREDENTIALS_SECRET_LABEL

NONCE = "test-nonce"
ACTIVE = testing.ActiveStatus("Vault integration ready")
WAITING = testing.WaitingStatus("Waiting for Vault information")
BLOCKED = testing.BlockedStatus("Missing vault-kv relation")


def vault_kv_nonce_secret():
    """Return the Vault nonce owned by this unit."""
    return testing.Secret(
        {"nonce": NONCE},
        label=NONCE_SECRET_LABEL,
        owner="unit",
    )


def ready_vault_kv_relation():
    """Return a relation with complete Vault information."""
    return testing.Relation(
        endpoint="vault-kv",
        remote_app_name="vault",
        local_unit_data={
            "nonce": NONCE,
            "egress_subnet": "10.0.0.0/24",
        },
        remote_app_data={
            "vault_url": "https://vault.example.com:8200",
            "ca_certificate": "test-ca-certificate",
            "mount": "charm-vaultlocker-keys",
            "credentials": json.dumps({NONCE: "secret:credentials"}),
        },
    )


def vault_kv_credentials_secret():
    """Return AppRole credentials shared by the vault provider."""
    return testing.Secret(
        {
            "role-id": "test-role-id",
            "role-secret-id": "test-role-secret-id",
        },
        id="secret:credentials",
    )


class TestVaultlockerCharm:
    """Test charm lifecycle and relation handling."""

    def test_install_without_vault_kv_creates_nonce_and_blocks(self, ctx):
        """Install creates a unit nonce and blocks until Vault is related."""
        state_out = ctx.run(ctx.on.install(), testing.State())

        secret = state_out.get_secret(label=NONCE_SECRET_LABEL)
        assert secret.owner == "unit"
        assert secret.tracked_content["nonce"]
        assert state_out.unit_status == BLOCKED

    def test_vault_kv_joined_requests_credentials(self, ctx):
        """Joining Vault publishes the credential request and sets Waiting."""
        relation = testing.Relation("vault-kv", remote_app_name="vault")
        network = testing.Network("vault-kv", egress_subnets=["10.0.0.0/24"])
        state_in = testing.State(
            leader=True,
            relations=[relation],
            networks=[network],
            secrets=[vault_kv_nonce_secret()],
        )

        state_out = ctx.run(ctx.on.relation_joined(relation, remote_unit=0), state_in)

        relation_out = state_out.get_relation(relation.id)
        assert relation_out.local_unit_data["nonce"] == NONCE
        assert relation_out.local_unit_data["egress_subnet"] == "10.0.0.0/24"
        assert relation_out.local_app_data["mount_suffix"] == "keys"
        assert state_out.unit_status == WAITING

    def test_vault_kv_complete_data_sets_active(self, ctx):
        """Ready reads the latest credentials and changes Waiting to Active."""
        relation = ready_vault_kv_relation()
        latest_content = {
            "role-id": "test-role-id",
            "role-secret-id": "updated-role-secret-id",
        }
        credentials = testing.Secret(
            {
                "role-id": "test-role-id",
                "role-secret-id": "old-role-secret-id",
            },
            latest_content=latest_content,
            id="secret:credentials",
        )
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret(), credentials],
            unit_status=WAITING,
        )

        state_out = ctx.run(
            ctx.on.relation_changed(relation, remote_unit=0),
            state_in,
        )

        config_dir = vaultlocker.CONFIG_PATH / "vaultlocker"
        ca_path = config_dir / "vault-ca.pem"
        config = configparser.ConfigParser()
        config.read(config_dir / "vaultlocker.conf")

        assert ca_path.read_text(encoding="utf-8") == "test-ca-certificate"
        assert dict(config["vault"]) == {
            "url": "https://vault.example.com:8200",
            "approle": "test-role-id",
            "secret_id": "updated-role-secret-id",
            "backend": "charm-vaultlocker-keys",
            "kv_version": "2",
            "ca_bundle": str(ca_path),
        }
        assert state_out.unit_status == ACTIVE

    def test_vault_kv_subnet_change_updates_request(self, ctx):
        """A network change updates the Vault request using the existing nonce."""
        relation = ready_vault_kv_relation()
        network = testing.Network("vault-kv", egress_subnets=["10.1.0.0/24"])
        state_in = testing.State(
            relations=[relation],
            networks=[network],
            secrets=[vault_kv_nonce_secret(), vault_kv_credentials_secret()],
            unit_status=ACTIVE,
        )

        state_out = ctx.run(ctx.on.update_status(), state_in)

        relation_out = state_out.get_relation(relation.id)
        assert relation_out.local_unit_data["egress_subnet"] == "10.1.0.0/24"
        assert relation_out.local_unit_data["nonce"] == NONCE
        assert state_out.unit_status == ACTIVE

    def test_vault_kv_credentials_removed_sets_waiting(self, ctx):
        """Removing the Vault credential reference changes Active to Waiting."""
        relation = ready_vault_kv_relation()
        relation.remote_app_data["credentials"] = "{}"
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret()],
            unit_status=ACTIVE,
        )

        state_out = ctx.run(ctx.on.relation_changed(relation, remote_unit=0), state_in)

        assert state_out.unit_status == WAITING

    def test_vault_kv_broken_sets_blocked(self, ctx):
        """Removing Vault blocks a unit."""
        relation = ready_vault_kv_relation()
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret()],
            unit_status=ACTIVE,
        )

        state_out = ctx.run(ctx.on.relation_broken(relation), state_in)

        assert state_out.unit_status == BLOCKED

    def test_vault_kv_credentials_changed_updates_config(self, ctx):
        """A new credential revision updates the Vaultlocker configuration."""
        latest_credentials = {
            "role-id": "test-role-id",
            "role-secret-id": "new-role-secret-id",
        }
        credentials = testing.Secret(
            {
                "role-id": "test-role-id",
                "role-secret-id": "old-role-secret-id",
            },
            latest_content=latest_credentials,
            id="secret:credentials",
            label=VAULT_CREDENTIALS_SECRET_LABEL,
        )
        relation = ready_vault_kv_relation()
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret(), credentials],
            unit_status=ACTIVE,
        )

        state_out = ctx.run(ctx.on.secret_changed(credentials), state_in)

        config = configparser.ConfigParser()
        config.read(vaultlocker.CONFIG_PATH / "vaultlocker" / "vaultlocker.conf")

        assert config["vault"]["secret_id"] == "new-role-secret-id"
        assert state_out.get_secret(id=credentials.id).tracked_content == latest_credentials
