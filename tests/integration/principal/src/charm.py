#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test principal charm providing the encrypted-device relation."""

import json
import logging

import ops

logger = logging.getLogger(__name__)

DEVICE_REQUESTS_FIELD = "device_requests"
DEVICE_RESULTS_FIELD = "device_results"


class EncryptedDevicePrincipalCharm(ops.CharmBase):
    """Minimal principal that publishes encrypted-device requests."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.framework.observe(self.on.publish_request_action, self._on_publish_request)
        self.framework.observe(self.on.get_results_action, self._on_get_results)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.update_status, self._on_start)

    def _on_start(self, _: ops.EventBase):
        """Report the unit as active."""
        self.unit.status = ops.ActiveStatus()

    def _relation(self):
        return self.model.get_relation("encrypted-device")

    def _on_publish_request(self, event: ops.ActionEvent):
        """Publish a device request for the target path."""
        relation = self._relation()
        if relation is None:
            event.fail("encrypted-device relation is not available")
            return

        target = event.params["target"]
        secret_id = event.params.get("existing-key-secret-id")
        if secret_id is not None and not secret_id.strip():
            event.fail("existing-key-secret-id must be nonempty when provided")
            return
        raw = relation.data[self.unit].get(DEVICE_REQUESTS_FIELD) or "{}"
        requests = json.loads(raw)
        requests[target] = {"existing_key_secret_id": secret_id} if secret_id else {}
        relation.data[self.unit][DEVICE_REQUESTS_FIELD] = json.dumps(requests)
        event.set_results({"published": target})

    def _on_get_results(self, event: ops.ActionEvent):
        """Return all device results published by vaultlocker."""
        relation = self._relation()
        if relation is None:
            event.fail("encrypted-device relation is not available")
            return

        results: dict = {}
        for unit in relation.units:
            raw = relation.data[unit].get(DEVICE_RESULTS_FIELD)
            if raw:
                results.update(json.loads(raw))
        event.set_results({"results": json.dumps(results)})


if __name__ == "__main__":
    ops.main(EncryptedDevicePrincipalCharm)
