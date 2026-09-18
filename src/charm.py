#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Vaultlocker charm."""

import logging
import secrets

import ops
from charms.vault_k8s.v0 import vault_kv
from vaultlocker_interfaces.encrypted_device import (
    DeviceRequestsChangedEvent,
    EncryptedDeviceRequires,
)

import vaultlocker

logger = logging.getLogger(__name__)

VAULT_KV_RELATION = "vault-kv"
ENCRYPTED_DEVICE_RELATION = "encrypted-device"
VAULT_KV_MOUNT_SUFFIX = "keys"
NONCE_SECRET_LABEL = "vault-kv-nonce"


class VaultlockerCharm(ops.CharmBase):
    """Vaultlocker subordinate charm."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        self.vault_kv = vault_kv.VaultKvRequires(
            self,
            VAULT_KV_RELATION,
            VAULT_KV_MOUNT_SUFFIX,
        )
        self.encrypted_device = EncryptedDeviceRequires(
            self,
            ENCRYPTED_DEVICE_RELATION,
        )

        framework.observe(self.on.install, self._on_install)
        framework.observe(
            self.vault_kv.on.connected,
            self._on_vault_kv_connected,
        )
        framework.observe(
            self.vault_kv.on.ready,
            self._on_vault_kv_ready,
        )
        framework.observe(
            self.encrypted_device.on.requests_changed,
            self._on_device_requests_changed,
        )
        framework.observe(
            self.on.secret_changed,
            self._on_secret_changed,
        )
        framework.observe(
            self.on.collect_unit_status,
            self._on_collect_vault_status,
        )
        framework.observe(
            self.on.collect_unit_status,
            self._on_collect_encrypted_device_status,
        )
        # There are intentionally no cleanup handlers for vault relation removal or
        # charm removal. The boot-unlock service operates outside of the charm lifecycle
        # and may still need the vault credentials to unlock registered devices.

    def _on_install(self, _: ops.InstallEvent):
        """Handle charm installation."""
        self._get_or_create_nonce()

    def _on_vault_kv_connected(self, event: vault_kv.VaultKvConnectedEvent):
        """Handle a connected vault-kv relation."""
        self._request_vault_credentials(event.relation)

    def _on_vault_kv_ready(self, event: vault_kv.VaultKvReadyEvent):
        """Handle the vault-kv relation ready."""
        # A deferred ready event could have been replayed after the relation is removed.
        if not event.relation.active:
            return

        if not self._write_vault_config(event.relation):
            # Vault information may be temporarily unavailable, so try again later.
            event.defer()
            return
        self._reconcile_encrypted_device_requests()

    def _on_device_requests_changed(self, event: DeviceRequestsChangedEvent):
        """Handle changed encrypted-device requests."""
        if event.unit is None:
            return
        self._reconcile_encrypted_device_requests()

    def _reconcile_encrypted_device_requests(self):
        """Reconcile the encrypted-device requests with the current state."""
        device_relation = self.model.get_relation(ENCRYPTED_DEVICE_RELATION)
        if device_relation is None or not device_relation.active:
            return

        requesting_unit = next(iter(device_relation.units), None)
        if requesting_unit is None:
            return

        try:
            requests = self.encrypted_device.get_device_requests(
                device_relation,
                requesting_unit,
            )
        except ValueError as error:
            logger.warning(
                "Invalid encrypted-device requests from %s: %s",
                requesting_unit.name,
                error,
            )
            return

        vault_relation = self.model.get_relation(VAULT_KV_RELATION)

        # Can not process device requests without a valid vault relation
        if vault_relation is None or not vault_relation.active or vault_relation.app is None:
            return

        if not vault_kv.is_provider_data_valid(vault_relation.data[vault_relation.app]):
            return

        if self._get_vault_credentials(vault_relation) is None:
            return

        config_path = vaultlocker.CONFIG_PATH / self.app.name / "vaultlocker.conf"
        if not config_path.is_file():
            return

        logger.info(
            "%d device request(s) from %s will be processed",
            len(requests),
            requesting_unit.name,
        )

    def _on_secret_changed(self, event: ops.SecretChangedEvent):
        """Update configuration when the Vault credentials change."""
        relation = self.model.get_relation(VAULT_KV_RELATION)
        if relation is None or relation.app is None:
            return

        if not vault_kv.is_provider_data_valid(relation.data[relation.app]):
            return

        credentials_secret_id = self.vault_kv.get_unit_credentials(relation)
        if not credentials_secret_id or event.secret.id != credentials_secret_id:
            return

        if not self._write_vault_config(relation):
            # The updated credentials may not be available yet, so try again later.
            event.defer()
            return
        self._reconcile_encrypted_device_requests()

    def _on_collect_vault_status(self, event: ops.CollectStatusEvent):
        """Report status using the current Vault relation data."""
        relation = self.model.get_relation(VAULT_KV_RELATION)
        if relation is None or not relation.active:
            event.add_status(ops.BlockedStatus("Missing vault-kv relation"))
            return

        if (
            relation.app is None
            or not vault_kv.is_provider_data_valid(relation.data[relation.app])
            or not self.vault_kv.get_unit_credentials(relation)
        ):
            event.add_status(ops.WaitingStatus("Waiting for Vault information"))
            return

        if self._get_vault_credentials(relation) is None:
            event.add_status(ops.WaitingStatus("Waiting for Vault credentials"))
            return

        config_dir = vaultlocker.CONFIG_PATH / self.app.name
        config_path = config_dir / "vaultlocker.conf"
        ca_path = config_dir / "vault-ca.pem"

        if not config_path.is_file() or not ca_path.is_file():
            event.add_status(ops.WaitingStatus("Waiting for Vault configuration"))
            return

        event.add_status(ops.ActiveStatus("Vault integration ready"))

    def _on_collect_encrypted_device_status(self, event: ops.CollectStatusEvent):
        """Report status for encrypted-device relation."""
        relation = self.model.get_relation(ENCRYPTED_DEVICE_RELATION)

        if relation is None or not relation.active:
            return

        principal_unit = next(iter(relation.units), None)
        if principal_unit is None:
            return

        try:
            self.encrypted_device.get_device_requests(
                relation,
                principal_unit,
            )
        except ValueError:
            event.add_status(
                ops.BlockedStatus(f"Invalid encrypted-device requests from {principal_unit.name}")
            )

    def _request_vault_credentials(self, relation: ops.Relation):
        """Request credentials for this unit."""
        binding = self.model.get_binding(relation)
        if binding is None:
            return

        egress_subnets = [str(subnet) for subnet in binding.network.egress_subnets]

        self.vault_kv.request_credentials(
            relation,
            egress_subnets,
            self._get_or_create_nonce(),
        )

    def _get_or_create_nonce(self) -> str:
        """Return the nonce identifying this unit, creating it if necessary."""
        try:
            secret = self.model.get_secret(label=NONCE_SECRET_LABEL)
        except ops.SecretNotFoundError:
            nonce = secrets.token_hex(16)
            self.unit.add_secret(
                {"nonce": nonce},
                label=NONCE_SECRET_LABEL,
                description="Nonce for vault-kv relation",
            )
            return nonce

        return secret.get_content(refresh=True)["nonce"]

    def _write_vault_config(self, relation: ops.Relation) -> bool:
        """Write Vaultlocker configuration and return whether it succeeded."""
        provider_data = relation.data[relation.app]

        if not vault_kv.is_provider_data_valid(provider_data):
            return False

        vault_url = self.vault_kv.get_vault_url(relation)
        ca_certificate = self.vault_kv.get_ca_certificate(relation)
        mount = self.vault_kv.get_mount(relation)

        if vault_url is None or ca_certificate is None or mount is None:
            return False

        credentials = self._get_vault_credentials(relation, refresh=True)
        if credentials is None:
            return False

        vaultlocker.write_vault_configuration(
            vaultlocker.CONFIG_PATH / self.app.name,
            vault_url=vault_url,
            ca_certificate=ca_certificate,
            mount=mount,
            role_id=credentials["role-id"],
            role_secret_id=credentials["role-secret-id"],
        )
        return True

    def _get_vault_credentials(
        self, relation: ops.Relation, refresh: bool = False
    ) -> dict[str, str] | None:
        """Return this unit's approle credentials when available."""
        secret_id = self.vault_kv.get_unit_credentials(relation)
        if not secret_id:
            return None

        try:
            secret = self.model.get_secret(id=secret_id)
            content = secret.get_content(refresh=refresh)
        except ops.ModelError as e:
            logger.warning("Unable to read vault AppRole credentials: %s", e)
            return None

        if not content.get("role-id") or not content.get("role-secret-id"):
            return None

        return content


if __name__ == "__main__":  # pragma: nocover
    ops.main(VaultlockerCharm)
