#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Vaultlocker charm."""

import logging
import secrets

import ops
from charms.vault_k8s.v0 import vault_kv

import vaultlocker

logger = logging.getLogger(__name__)

VAULT_KV_RELATION = "vault-kv"
VAULT_KV_MOUNT_SUFFIX = "keys"
NONCE_SECRET_LABEL = "vault-kv-nonce"
VAULT_CREDENTIALS_SECRET_LABEL = "vault-kv-credentials"


class VaultlockerCharm(ops.CharmBase):
    """Vaultlocker subordinate charm."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        self.vault_kv = vault_kv.VaultKvRequires(
            self,
            VAULT_KV_RELATION,
            VAULT_KV_MOUNT_SUFFIX,
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
            self.on.secret_changed,
            self._on_secret_changed,
        )
        framework.observe(
            self.on.update_status,
            self._on_update_status,
        )
        framework.observe(
            self.on.collect_unit_status,
            self._on_collect_vault_status,
        )

    def _on_install(self, _: ops.InstallEvent):
        """Handle charm installation."""
        self._get_or_create_nonce()

    def _on_vault_kv_connected(self, event: vault_kv.VaultKvConnectedEvent):
        """Handle a connected vault-kv relation."""
        self._request_vault_credentials(event.relation)

    def _on_vault_kv_ready(self, event: vault_kv.VaultKvReadyEvent):
        """Handle the vault-kv relation ready."""
        self._write_vault_config(event.relation)

    def _on_secret_changed(self, event: ops.SecretChangedEvent):
        """Update configuration when the Vault credentials change."""
        if event.secret.label != VAULT_CREDENTIALS_SECRET_LABEL:
            return

        relation = self.model.get_relation(VAULT_KV_RELATION)
        if relation is not None:
            self._write_vault_config(relation)

    def _on_update_status(self, _: ops.UpdateStatusEvent):
        """Handle status updates.."""
        # Refresh the Vault credential request using current network information.
        relation = self.model.get_relation(VAULT_KV_RELATION)
        if relation is not None:
            self._request_vault_credentials(relation)

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

        event.add_status(ops.ActiveStatus("Vault integration ready"))

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

    def _write_vault_config(self, relation: ops.Relation) -> None:
        """Write Vaultlocker configuration from vault-kv relation data."""
        provider_data = relation.data[relation.app]

        if not vault_kv.is_provider_data_valid(provider_data):
            return

        vault_url = self.vault_kv.get_vault_url(relation)
        ca_certificate = self.vault_kv.get_ca_certificate(relation)
        mount = self.vault_kv.get_mount(relation)

        if vault_url is None or ca_certificate is None or mount is None:
            return

        credentials = self._get_vault_credentials(relation, refresh=True)
        if credentials is None:
            return

        vaultlocker.write_vault_configuration(
            vaultlocker.CONFIG_PATH / self.app.name,
            vault_url=vault_url,
            ca_certificate=ca_certificate,
            mount=mount,
            role_id=credentials["role-id"],
            role_secret_id=credentials["role-secret-id"],
        )

    def _get_vault_credentials(
        self, relation: ops.Relation, refresh: bool = False
    ) -> dict[str, str] | None:
        """Return this unit's approle credentials when available."""
        secret_id = self.vault_kv.get_unit_credentials(relation)
        if not secret_id:
            return None

        try:
            secret = self.model.get_secret(
                id=secret_id,
                label=VAULT_CREDENTIALS_SECRET_LABEL,
            )
            content = secret.get_content(refresh=refresh)
        except ops.ModelError as e:
            logger.warning("Unable to read vault AppRole credentials: %s", e)
            return None

        if not content.get("role-id") or not content.get("role-secret-id"):
            return None

        return content


if __name__ == "__main__":  # pragma: nocover
    ops.main(VaultlockerCharm)
