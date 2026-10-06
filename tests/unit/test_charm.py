# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://canonical.com/juju/docs/ops/latest/explanation/testing/

"""Unit tests for the Vaultlocker charm."""

import configparser
import json
from unittest import mock

import pytest
from charmlibs import snap
from ops import testing
from scenario.errors import UncaughtCharmError

import charm
import vaultlocker
import vaultlocker_cli
from charm import NONCE_SECRET_LABEL, VaultlockerCharm
from local_metadata import (
    REQUEST_TYPE_ENCRYPT,
    REQUEST_TYPE_ENROLL,
    STATE_FILE_NAME,
    LocalMetadataStore,
)

DEVICE_TARGET = "/dev/disk/by-id/device-a"
NONCE = "test-nonce"
VAULT_READY_STATUS = testing.ActiveStatus("Vault integration ready")
WAITING_FOR_VAULT_STATUS = testing.WaitingStatus("Waiting for Vault information")
MISSING_VAULT_RELATION_STATUS = testing.BlockedStatus("Missing vault-kv relation")
INVALID_DEVICE_REQUESTS_STATUS = testing.BlockedStatus(
    "Invalid encrypted-device requests from principal/0"
)


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


def encrypted_device_relation(
    device_requests: str,
) -> testing.SubordinateRelation:
    """Return an encrypted-device relation containing unit requests."""
    return testing.SubordinateRelation(
        endpoint="encrypted-device",
        remote_app_name="principal",
        remote_unit_data={
            "device_requests": device_requests,
        },
    )


def create_vault_config_files():
    """Create an existing Vaultlocker configuration  and ca file."""
    config_dir = vaultlocker.CONFIG_PATH / "vaultlocker"
    config_path = config_dir / "vaultlocker.conf"
    ca_path = config_dir / "vault-ca.pem"
    config_dir.mkdir(parents=True)
    config_path.touch()
    ca_path.touch()


class TestVaultlockerCharm:
    """Test charm lifecycle and relation handling."""

    def test_install_without_vault_kv_creates_nonce_and_blocks(self, ctx):
        """Install creates a unit nonce and blocks until Vault is related."""
        with mock.patch("charm.snap.install"):
            state_out = ctx.run(ctx.on.install(), testing.State())

        secret = state_out.get_secret(label=NONCE_SECRET_LABEL)
        assert secret.owner == "unit"
        assert secret.tracked_content["nonce"]
        assert state_out.unit_status == MISSING_VAULT_RELATION_STATUS

    def test_install_installs_vaultlocker_snap(self, ctx):
        """Install installs the vaultlocker snap from the default channel."""
        with mock.patch("charm.snap.install") as install:
            state_out = ctx.run(ctx.on.install(), testing.State())

        install.assert_called_once_with("vaultlocker", channel="latest/stable")
        assert state_out.unit_status == MISSING_VAULT_RELATION_STATUS

    def test_install_respects_configured_channel(self, ctx):
        """Install uses the configured snap channel."""
        with mock.patch("charm.snap.install") as install:
            ctx.run(
                ctx.on.install(),
                testing.State(config={"snap-channel": "edge"}),
            )

        install.assert_called_once_with("vaultlocker", channel="edge")

    def test_install_snap_failure_fails_hook(self, ctx, tmp_path):
        """A snapd failure fails the install hook."""
        ctx.charm_root = tmp_path
        with mock.patch("charm.snap.install", side_effect=snap.Error("snapd unavailable")):
            with pytest.raises(UncaughtCharmError, match="snapd unavailable") as error:
                ctx.run(ctx.on.install(), testing.State())

        assert isinstance(error.value.__cause__, snap.Error)
        ctx._tmp.cleanup()

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
        assert state_out.unit_status == WAITING_FOR_VAULT_STATUS

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
            unit_status=WAITING_FOR_VAULT_STATUS,
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
        assert state_out.unit_status == VAULT_READY_STATUS

    def test_vault_kv_subnet_change_updates_request(self, ctx):
        """A network change updates the Vault request using the existing nonce."""
        relation = ready_vault_kv_relation()
        network = testing.Network("vault-kv", egress_subnets=["10.1.0.0/24"])
        state_in = testing.State(
            relations=[relation],
            networks=[network],
            secrets=[vault_kv_nonce_secret(), vault_kv_credentials_secret()],
            unit_status=VAULT_READY_STATUS,
        )

        state_out = ctx.run(ctx.on.config_changed(), state_in)

        relation_out = state_out.get_relation(relation.id)
        assert relation_out.local_unit_data["egress_subnet"] == "10.1.0.0/24"
        assert relation_out.local_unit_data["nonce"] == NONCE

    def test_vault_kv_credentials_removed_sets_waiting(self, ctx):
        """Removing the Vault credential reference changes Active to Waiting."""
        relation = ready_vault_kv_relation()
        relation.remote_app_data["credentials"] = "{}"
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret()],
            unit_status=VAULT_READY_STATUS,
        )

        state_out = ctx.run(ctx.on.relation_changed(relation, remote_unit=0), state_in)

        assert state_out.unit_status == WAITING_FOR_VAULT_STATUS

    def test_vault_kv_broken_sets_blocked(self, ctx):
        """Removing Vault blocks a unit."""
        relation = ready_vault_kv_relation()
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret()],
            unit_status=VAULT_READY_STATUS,
        )

        state_out = ctx.run(ctx.on.relation_broken(relation), state_in)

        assert state_out.unit_status == MISSING_VAULT_RELATION_STATUS

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
        )
        relation = ready_vault_kv_relation()
        state_in = testing.State(
            relations=[relation],
            secrets=[vault_kv_nonce_secret(), credentials],
            unit_status=VAULT_READY_STATUS,
        )

        state_out = ctx.run(ctx.on.secret_changed(credentials), state_in)

        config = configparser.ConfigParser()
        config.read(vaultlocker.CONFIG_PATH / "vaultlocker" / "vaultlocker.conf")

        assert config["vault"]["secret_id"] == "new-role-secret-id"
        assert state_out.get_secret(id=credentials.id).tracked_content == latest_credentials

    def test_valid_encrypted_device_requests_are_accepted(self, ctx):
        """A valid device request is accepted."""
        vault_relation = ready_vault_kv_relation()
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        create_vault_config_files()

        state_in = testing.State(
            relations=[vault_relation, device_relation],
            secrets=[
                vault_kv_nonce_secret(),
                vault_kv_credentials_secret(),
            ],
            unit_status=VAULT_READY_STATUS,
        )

        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-1", mapper_path="/dev/mapper/crypt-uuid-1"
        )
        with mock.patch.object(charm.vaultlocker_cli, "run_encrypt", return_value=result):
            state_out = ctx.run(
                ctx.on.relation_changed(device_relation, remote_unit=0),
                state_in,
            )

        assert state_out.unit_status == VAULT_READY_STATUS

    def test_invalid_encrypted_device_requests_set_blocked(self, ctx):
        """Malformed device requests block without failing the hook."""
        vault_relation = ready_vault_kv_relation()
        device_relation = encrypted_device_relation("[]")
        state_in = testing.State(
            relations=[vault_relation, device_relation],
            secrets=[
                vault_kv_nonce_secret(),
                vault_kv_credentials_secret(),
            ],
            unit_status=VAULT_READY_STATUS,
        )

        state_out = ctx.run(
            ctx.on.relation_changed(
                device_relation,
                remote_unit=0,
            ),
            state_in,
        )

        assert state_out.unit_status == INVALID_DEVICE_REQUESTS_STATUS

    def test_corrected_encrypted_device_requests_clear_blocked(self, ctx):
        """Correcting device requests clears the invalid-request status."""
        vault_relation = ready_vault_kv_relation()
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        create_vault_config_files()

        state_in = testing.State(
            relations=[vault_relation, device_relation],
            secrets=[
                vault_kv_nonce_secret(),
                vault_kv_credentials_secret(),
            ],
            unit_status=INVALID_DEVICE_REQUESTS_STATUS,
        )

        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-1", mapper_path="/dev/mapper/crypt-uuid-1"
        )
        with mock.patch.object(charm.vaultlocker_cli, "run_encrypt", return_value=result):
            state_out = ctx.run(
                ctx.on.relation_changed(device_relation, remote_unit=0),
                state_in,
            )

        assert state_out.unit_status == VAULT_READY_STATUS

    def test_vault_ready_reconciles_pending_device_requests(self, ctx):
        """Previously received device requests are retried after vault becomes ready."""
        vault_relation = ready_vault_kv_relation()
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = testing.State(
            relations=[vault_relation, device_relation],
            secrets=[
                vault_kv_nonce_secret(),
                vault_kv_credentials_secret(),
            ],
            unit_status=WAITING_FOR_VAULT_STATUS,
        )

        with mock.patch.object(
            VaultlockerCharm,
            "_reconcile_encrypted_device_requests",
        ) as reconcile:
            state_out = ctx.run(
                ctx.on.relation_changed(
                    vault_relation,
                    remote_unit=0,
                ),
                state_in,
            )

        reconcile.assert_called_once()
        assert state_out.unit_status == VAULT_READY_STATUS


@pytest.fixture
def vault_config():
    """Create the Vaultlocker configuration file."""
    config_dir = vaultlocker.CONFIG_PATH / "vaultlocker"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "vaultlocker.conf"
    config_path.write_text("[vault]\n", encoding="utf-8")
    return config_path


@pytest.fixture
def metadata_store():
    """Return the device state store used by the charm."""
    return LocalMetadataStore(vaultlocker.CONFIG_PATH / "vaultlocker" / STATE_FILE_NAME)


class TestDeviceReconciliation:
    """Test the device provisioning reconciliation loop."""

    def _state(self, device_relation, extra_secrets=()):
        secrets = [
            vault_kv_nonce_secret(),
            vault_kv_credentials_secret(),
            *extra_secrets,
        ]
        return testing.State(
            relations=[ready_vault_kv_relation(), device_relation],
            secrets=secrets,
            unit_status=VAULT_READY_STATUS,
        )

    def test_reconcile_encrypts_new_device(self, ctx, vault_config, metadata_store):
        """A fresh encryption request is provisioned and published."""
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)
        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-1", mapper_path="/dev/mapper/crypt-uuid-1"
        )

        with mock.patch.object(
            charm.vaultlocker_cli, "run_encrypt", return_value=result
        ) as run_encrypt:
            state_out = ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        run_encrypt.assert_called_once_with(
            DEVICE_TARGET,
            vaultlocker.CONFIG_PATH / "vaultlocker" / "vaultlocker.conf",
        )
        relation_out = state_out.get_relation(device_relation.id)
        assert json.loads(relation_out.local_unit_data["device_results"]) == {
            DEVICE_TARGET: {
                "mapper_path": "/dev/mapper/crypt-uuid-1",
                "luks_uuid": "uuid-1",
            }
        }
        state = metadata_store.get(DEVICE_TARGET)
        assert state.completed is True
        assert state.request_type == REQUEST_TYPE_ENCRYPT

    def test_reconcile_enrolls_with_secret(self, ctx, vault_config, metadata_store):
        """An enrollment request reads the passphrase and enrolls the device."""
        existing_key = testing.Secret({"passphrase": "s3cret"}, id="secret:existing-key")
        requests = json.dumps({DEVICE_TARGET: {"existing_key_secret_id": "secret:existing-key"}})
        device_relation = encrypted_device_relation(requests)
        state_in = self._state(device_relation, extra_secrets=[existing_key])
        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-2", mapper_path="/dev/mapper/crypt-uuid-2"
        )

        with mock.patch.object(
            charm.vaultlocker_cli, "run_enroll", return_value=result
        ) as run_enroll:
            ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        run_enroll.assert_called_once_with(
            DEVICE_TARGET,
            vaultlocker.CONFIG_PATH / "vaultlocker" / "vaultlocker.conf",
            "s3cret",
        )
        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.completed is True
        assert state.request_type == REQUEST_TYPE_ENROLL

    def test_reconcile_skips_completed_device(self, ctx, vault_config, metadata_store):
        """A completed device is republished without running vaultlocker again."""
        metadata_store.mark_completed(
            DEVICE_TARGET, REQUEST_TYPE_ENCRYPT, "uuid-1", "/dev/mapper/crypt-uuid-1"
        )
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)

        with (
            mock.patch.object(charm.vaultlocker_cli, "run_encrypt") as run_encrypt,
            mock.patch.object(charm.vaultlocker_cli, "run_enroll") as run_enroll,
        ):
            state_out = ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        run_encrypt.assert_not_called()
        run_enroll.assert_not_called()
        relation_out = state_out.get_relation(device_relation.id)
        assert json.loads(relation_out.local_unit_data["device_results"]) == {
            DEVICE_TARGET: {
                "mapper_path": "/dev/mapper/crypt-uuid-1",
                "luks_uuid": "uuid-1",
            }
        }

    def test_reconcile_retries_recorded_failure(self, ctx, vault_config, metadata_store):
        """A later event retries a request that previously failed."""
        metadata_store.record_failure(DEVICE_TARGET, REQUEST_TYPE_ENCRYPT, "vault unavailable")
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)
        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-1", mapper_path="/dev/mapper/crypt-uuid-1"
        )

        with mock.patch.object(
            charm.vaultlocker_cli, "run_encrypt", return_value=result
        ) as run_encrypt:
            ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        run_encrypt.assert_called_once()
        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.completed is True
        assert state.last_failure is None

    def test_reconcile_records_tool_failure(self, ctx, vault_config, metadata_store):
        """A tool failure is recorded for status and a later attempt."""
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)
        error = vaultlocker_cli.VaultlockerCliError("vault unavailable")

        with mock.patch.object(charm.vaultlocker_cli, "run_encrypt", side_effect=error):
            state_out = ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.completed is False
        assert state.last_failure is not None
        assert state.last_failure.message == "vault unavailable"
        relation_out = state_out.get_relation(device_relation.id)
        assert json.loads(relation_out.local_unit_data.get("device_results", "{}")) == {}

    def test_reconcile_records_failure_when_passphrase_is_missing(
        self, ctx, vault_config, metadata_store
    ):
        """An enrollment secret without a passphrase is a recorded failure."""
        other_secret = testing.Secret({"other": "value"}, id="secret:no-passphrase")
        requests = json.dumps({DEVICE_TARGET: {"existing_key_secret_id": "secret:no-passphrase"}})
        device_relation = encrypted_device_relation(requests)
        state_in = self._state(device_relation, extra_secrets=[other_secret])

        ctx.run(ctx.on.relation_changed(device_relation, remote_unit=0), state_in)

        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.last_failure is not None
        assert state.last_failure.message == "existing key secret does not contain a passphrase"

    def test_passphrase_secret_change_retries_enrollment(self, ctx, vault_config, metadata_store):
        """Updating a requested passphrase retries an incomplete enrollment."""
        metadata_store.record_failure(
            DEVICE_TARGET, REQUEST_TYPE_ENROLL, "existing key secret does not contain a passphrase"
        )
        existing_key = testing.Secret(
            {"other": "value"},
            latest_content={"passphrase": "updated-passphrase"},
            id="secret:existing-key",
        )
        requests = json.dumps({DEVICE_TARGET: {"existing_key_secret_id": existing_key.id}})
        device_relation = encrypted_device_relation(requests)
        state_in = self._state(device_relation, extra_secrets=[existing_key])
        result = vaultlocker_cli.VaultlockerResult(
            uuid="uuid-2", mapper_path="/dev/mapper/crypt-uuid-2"
        )

        with mock.patch.object(
            charm.vaultlocker_cli, "run_enroll", return_value=result
        ) as run_enroll:
            state_out = ctx.run(ctx.on.secret_changed(existing_key), state_in)

        run_enroll.assert_called_once_with(
            DEVICE_TARGET,
            vault_config,
            "updated-passphrase",
        )
        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.completed is True
        assert state.last_failure is None
        relation_out = state_out.get_relation(device_relation.id)
        assert json.loads(relation_out.local_unit_data["device_results"]) == {
            DEVICE_TARGET: {
                "mapper_path": "/dev/mapper/crypt-uuid-2",
                "luks_uuid": "uuid-2",
            }
        }

    def test_unrelated_secret_change_does_not_retry_enrollment(
        self, ctx, vault_config, metadata_store
    ):
        """A different secret change does not rerun a pending enrollment."""
        metadata_store.record_failure(DEVICE_TARGET, REQUEST_TYPE_ENROLL, "passphrase unavailable")
        existing_key = testing.Secret({"passphrase": "s3cret"}, id="secret:existing-key")
        unrelated = testing.Secret(
            {"value": "old"}, latest_content={"value": "new"}, id="secret:unrelated"
        )
        requests = json.dumps({DEVICE_TARGET: {"existing_key_secret_id": existing_key.id}})
        device_relation = encrypted_device_relation(requests)
        state_in = self._state(device_relation, extra_secrets=[existing_key, unrelated])

        with mock.patch.object(charm.vaultlocker_cli, "run_enroll") as run_enroll:
            ctx.run(ctx.on.secret_changed(unrelated), state_in)

        run_enroll.assert_not_called()
        state = metadata_store.get(DEVICE_TARGET)
        assert state is not None
        assert state.completed is False
        assert state.last_failure is not None

    def test_passphrase_secret_change_does_not_rerun_completed_enrollment(
        self, ctx, vault_config, metadata_store
    ):
        """A completed request stays complete when its passphrase secret changes."""
        metadata_store.mark_completed(
            DEVICE_TARGET, REQUEST_TYPE_ENROLL, "uuid-2", "/dev/mapper/crypt-uuid-2"
        )
        existing_key = testing.Secret(
            {"passphrase": "old"},
            latest_content={"passphrase": "updated"},
            id="secret:existing-key",
        )
        requests = json.dumps({DEVICE_TARGET: {"existing_key_secret_id": existing_key.id}})
        device_relation = encrypted_device_relation(requests)
        state_in = self._state(device_relation, extra_secrets=[existing_key])

        with mock.patch.object(charm.vaultlocker_cli, "run_enroll") as run_enroll:
            state_out = ctx.run(ctx.on.secret_changed(existing_key), state_in)

        run_enroll.assert_not_called()
        relation_out = state_out.get_relation(device_relation.id)
        assert json.loads(relation_out.local_unit_data["device_results"]) == {
            DEVICE_TARGET: {
                "mapper_path": "/dev/mapper/crypt-uuid-2",
                "luks_uuid": "uuid-2",
            }
        }

    def test_status_blocked_on_recorded_failure(self, ctx, metadata_store):
        """A recorded device failure blocks the unit."""
        create_vault_config_files()
        metadata_store.record_failure(DEVICE_TARGET, "encrypt", "vault down")
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)

        state_out = ctx.run(ctx.on.update_status(), state_in)

        assert state_out.unit_status == testing.BlockedStatus(
            "1 device request(s) failed; see the charm logs for details"
        )

    def test_status_active_without_failures(self, ctx):
        """No device failures leaves the unit active."""
        create_vault_config_files()
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)

        state_out = ctx.run(ctx.on.update_status(), state_in)

        assert state_out.unit_status == VAULT_READY_STATUS

    def test_status_ignores_failures_for_unrequested_devices(self, ctx, metadata_store):
        """Failures for unrequested devices do not affect status."""
        create_vault_config_files()
        metadata_store.record_failure("/dev/disk/by-id/other", "encrypt", "vault down")
        device_relation = encrypted_device_relation(json.dumps({DEVICE_TARGET: {}}))
        state_in = self._state(device_relation)

        state_out = ctx.run(ctx.on.update_status(), state_in)

        assert state_out.unit_status == VAULT_READY_STATUS
