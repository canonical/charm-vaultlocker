# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the encrypted-device library."""

import json

import pytest
from ops import testing
from ops.charm import CharmBase
from ops.model import ActiveStatus
from vaultlocker_interfaces.encrypted_device import (
    DeviceRequest,
    DeviceRequestsChangedEvent,
    DeviceResult,
    DeviceResultsChangedEvent,
    EncryptedDeviceProvides,
    EncryptedDeviceRequires,
    parse_device_requests,
    parse_device_results,
    serialize_device_requests,
    serialize_device_results,
)

TARGET = "/dev/disk/by-id/device-a"

_REQUIRER_METADATA = {
    "name": "vaultlocker",
    "requires": {
        "encrypted-device": {
            "interface": "encrypted-device",
        }
    },
}
_PROVIDER_METADATA = {
    "name": "principal",
    "provides": {
        "encrypted-device": {
            "interface": "encrypted-device",
        }
    },
}


class _RequirerCharm(CharmBase):
    """A test charm used to test the requirer object."""

    def __init__(self, *args):
        super().__init__(*args)
        self.encrypted_device = EncryptedDeviceRequires(
            self,
            "encrypted-device",
        )
        self.framework.observe(
            self.encrypted_device.on.requests_changed,
            self._on_requests_changed,
        )
        self.framework.observe(
            self.on.config_changed,
            self._on_config_changed,
        )

    def _on_requests_changed(
        self,
        event: DeviceRequestsChangedEvent,
    ) -> None:
        """Read requests when the library reports a change."""
        if event.unit is None:
            return

        requests = self.encrypted_device.get_device_requests(
            event.relation,
            event.unit,
        )
        self.unit.status = ActiveStatus(f"Received {len(requests)} device requests")

    def _on_config_changed(self, _) -> None:
        """Write a result so the unit databag can be checked."""
        relation = self.model.get_relation("encrypted-device")
        if relation is None:
            return

        self.encrypted_device.set_device_results(
            relation,
            [
                DeviceResult(
                    target=TARGET,
                    mapper_path="/dev/mapper/crypt-a",
                    luks_uuid="uuid-a",
                )
            ],
        )


class _ProviderCharm(CharmBase):
    """A test charm used to test the provider object."""

    def __init__(self, *args):
        super().__init__(*args)
        self.encrypted_device = EncryptedDeviceProvides(
            self,
            "encrypted-device",
        )
        self.framework.observe(
            self.encrypted_device.on.results_changed,
            self._on_results_changed,
        )
        self.framework.observe(
            self.on.config_changed,
            self._on_config_changed,
        )

    def _on_results_changed(
        self,
        event: DeviceResultsChangedEvent,
    ) -> None:
        """Read results when the library reports a change."""
        if event.unit is None:
            return

        results = self.encrypted_device.get_device_results(
            event.relation,
            event.unit,
        )
        self.unit.status = ActiveStatus(f"Received {len(results)} device results")

    def _on_config_changed(self, _) -> None:
        """Write a request so the unit databag can be checked."""
        relation = self.model.get_relation("encrypted-device")
        if relation is None:
            return

        self.encrypted_device.set_device_requests(
            relation,
            [
                DeviceRequest(
                    target=TARGET,
                )
            ],
        )


class TestSerializeDeviceRequests:
    """Test serializing requests for relation data."""

    def test_empty_request_list(self):
        """An empty request list becomes an empty JSON object."""
        assert serialize_device_requests([]) == "{}"

    def test_valid_requests(self):
        """Valid requests are serialized correctly."""
        other_target = "/dev/disk/by-id/device-b"
        secret_id = "secret:existing-key"
        requests = [
            DeviceRequest(target=TARGET),
            DeviceRequest(
                target=other_target,
                existing_key_secret_id=secret_id,
            ),
        ]

        raw = serialize_device_requests(requests)

        assert json.loads(raw) == {
            TARGET: {},
            other_target: {"existing_key_secret_id": secret_id},
        }
        assert parse_device_requests(raw) == requests

    def test_request_order_does_not_change_output(self):
        """Equivalent request lists produce the same relation value."""
        other_target = "/dev/disk/by-id/device-b"
        first = DeviceRequest(target=TARGET)
        second = DeviceRequest(target=other_target)

        assert serialize_device_requests([first, second]) == serialize_device_requests(
            [second, first]
        )

    def test_duplicate_target(self):
        """The same target cannot be serialized twice."""
        requests = [
            DeviceRequest(target=TARGET),
            DeviceRequest(target=TARGET),
        ]

        with pytest.raises(ValueError):
            serialize_device_requests(requests)

    def test_target_must_be_an_absolute_path(self):
        """A relative target is not written to relation data."""
        requests = [DeviceRequest(target="dev/device-a")]

        with pytest.raises(ValueError):
            serialize_device_requests(requests)

    @pytest.mark.parametrize("secret_id", ["", " ", 1])
    def test_invalid_secret_id(self, secret_id):
        """An empty or non-string existing key secret ID is rejected."""
        requests = [
            DeviceRequest(
                target=TARGET,
                existing_key_secret_id=secret_id,
            )
        ]

        with pytest.raises(ValueError):
            serialize_device_requests(requests)


class TestParseDeviceRequests:
    """Test parsing requests from relation data."""

    def test_empty_request_map(self):
        """An empty map contains no requests."""
        assert parse_device_requests("{}") == []

    def test_valid_requests(self):
        """Valid requests are parsed correctly."""
        other_target = "/dev/disk/by-id/device-b"
        secret_id = "secret:existing-key"
        raw = json.dumps(
            {
                TARGET: {},
                other_target: {"existing_key_secret_id": secret_id},
            }
        )

        requests = parse_device_requests(raw)

        requests_by_target = {request.target: request for request in requests}
        assert requests_by_target == {
            TARGET: DeviceRequest(target=TARGET),
            other_target: DeviceRequest(
                target=other_target,
                existing_key_secret_id=secret_id,
            ),
        }

    def test_invalid_json(self):
        """Invalid JSON is rejected."""
        with pytest.raises(ValueError):
            parse_device_requests("not-json")

    def test_top_level_value_must_be_an_object(self):
        """The top-level value must be a device-keyed JSON object."""
        with pytest.raises(ValueError):
            parse_device_requests("[]")

    def test_request_value_must_be_an_object(self):
        """Each device request value must be a JSON object."""
        raw = json.dumps({TARGET: []})

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    def test_target_must_be_an_absolute_path(self):
        """A relative device target is rejected."""
        raw = json.dumps({"dev/device-a": {}})

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    def test_unsupported_request_field(self):
        """An unknown request field is rejected."""
        raw = json.dumps({TARGET: {"secret_id": "secret:existing-key"}})

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    @pytest.mark.parametrize("secret_id", ["", " "])
    def test_empty_secret_id(self, secret_id):
        """An empty existing key secret ID is rejected."""
        raw = json.dumps({TARGET: {"existing_key_secret_id": secret_id}})

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    def test_secret_id_must_be_a_string(self):
        """An existing key secret ID must be a string."""
        raw = json.dumps({TARGET: {"existing_key_secret_id": None}})

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    def test_duplicate_target(self):
        """The same target appearing more than once should raise a ValueError."""
        raw = (
            '{"/dev/disk/by-id/device-a": {}, '
            '"/dev/disk/by-id/device-a": '
            '{"existing_key_secret_id": "secret:existing-key"}}'
        )

        with pytest.raises(ValueError):
            parse_device_requests(raw)

    def test_error_does_not_include_request_content(self):
        """Validation errors do not include possible secret values."""
        secret = "do-not-show-this"
        raw = json.dumps({TARGET: {"passphrase": secret}})

        with pytest.raises(ValueError) as error:
            parse_device_requests(raw)

        assert secret not in str(error.value)


class TestSerializeDeviceResults:
    """Test serializing results for relation data."""

    def test_empty_result_list(self):
        """An empty result list becomes an empty JSON object."""
        assert serialize_device_results([]) == "{}"

    def test_valid_results(self):
        """Completed device results are serialized."""
        mapper_path = "/dev/mapper/crypt-a1b2c3d4"
        luks_uuid = "a1b2c3d4"
        results = [
            DeviceResult(
                target=TARGET,
                mapper_path=mapper_path,
                luks_uuid=luks_uuid,
            )
        ]

        raw = serialize_device_results(results)

        assert json.loads(raw) == {
            TARGET: {
                "mapper_path": mapper_path,
                "luks_uuid": luks_uuid,
            }
        }
        assert parse_device_results(raw) == results

    def test_result_order_does_not_change_output(self):
        """Equivalent result lists produce the same relation value."""
        other_target = "/dev/disk/by-id/device-b"
        first = DeviceResult(
            target=TARGET,
            mapper_path="/dev/mapper/crypt-a",
            luks_uuid="uuid-a",
        )
        second = DeviceResult(
            target=other_target,
            mapper_path="/dev/mapper/crypt-b",
            luks_uuid="uuid-b",
        )

        assert serialize_device_results([first, second]) == serialize_device_results(
            [second, first]
        )

    def test_duplicate_target(self):
        """The same target cannot be serialized twice."""
        result = DeviceResult(
            target=TARGET,
            mapper_path="/dev/mapper/crypt-a",
            luks_uuid="uuid-a",
        )

        with pytest.raises(ValueError):
            serialize_device_results([result, result])

    def test_target_must_be_an_absolute_path(self):
        """A relative target is not written to relation data."""
        result = DeviceResult(
            target="dev/device-a",
            mapper_path="/dev/mapper/crypt-a",
            luks_uuid="uuid-a",
        )

        with pytest.raises(ValueError):
            serialize_device_results([result])

    def test_mapper_path_must_be_an_absolute_path(self):
        """A relative mapper path is not written to relation data."""
        result = DeviceResult(
            target=TARGET,
            mapper_path="dev/mapper/crypt-a",
            luks_uuid="uuid-a",
        )

        with pytest.raises(ValueError):
            serialize_device_results([result])

    @pytest.mark.parametrize("luks_uuid", ["", " ", 1])
    def test_invalid_luks_uuid(self, luks_uuid):
        """An empty or non-string LUKS UUID is rejected."""
        result = DeviceResult(
            target=TARGET,
            mapper_path="/dev/mapper/crypt-a",
            luks_uuid=luks_uuid,
        )

        with pytest.raises(ValueError):
            serialize_device_results([result])


class TestParseDeviceResults:
    """Test parsing results from relation data."""

    def test_empty_result_map(self):
        """An empty map contains no results."""
        assert parse_device_results("{}") == []

    def test_valid_results(self):
        """A completed device result is parsed."""
        mapper_path = "/dev/mapper/crypt-a1b2c3d4"
        luks_uuid = "a1b2c3d4"
        raw = json.dumps(
            {
                TARGET: {
                    "mapper_path": mapper_path,
                    "luks_uuid": luks_uuid,
                }
            }
        )

        assert parse_device_results(raw) == [
            DeviceResult(
                target=TARGET,
                mapper_path=mapper_path,
                luks_uuid=luks_uuid,
            )
        ]

    def test_invalid_json(self):
        """Invalid JSON is rejected."""
        with pytest.raises(ValueError):
            parse_device_results("not-json")

    def test_top_level_value_must_be_an_object(self):
        """The top-level value must be a device-keyed JSON object."""
        with pytest.raises(ValueError):
            parse_device_results("[]")

    def test_result_value_must_be_an_object(self):
        """Each device result value must be a JSON object."""
        raw = json.dumps({TARGET: []})

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_target_must_be_an_absolute_path(self):
        """A relative device target is rejected."""
        raw = json.dumps(
            {
                "dev/device-a": {
                    "mapper_path": "/dev/mapper/crypt-a",
                    "luks_uuid": "uuid-a",
                }
            }
        )

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_unsupported_result_field(self):
        """An unknown result field is rejected."""
        raw = json.dumps(
            {
                TARGET: {
                    "mapper_path": "/dev/mapper/crypt-a",
                    "luks_uuid": "uuid-a",
                    "status": "ready",
                }
            }
        )

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_mapper_path_is_required(self):
        """A result without a mapper path is rejected."""
        raw = json.dumps({TARGET: {"luks_uuid": "uuid-a"}})

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_mapper_path_must_be_an_absolute_path(self):
        """A relative mapper path is rejected."""
        raw = json.dumps(
            {
                TARGET: {
                    "mapper_path": "dev/mapper/crypt-a",
                    "luks_uuid": "uuid-a",
                }
            }
        )

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_luks_uuid_is_required(self):
        """A result without a LUKS UUID is rejected."""
        raw = json.dumps({TARGET: {"mapper_path": "/dev/mapper/crypt-a"}})

        with pytest.raises(ValueError):
            parse_device_results(raw)

    @pytest.mark.parametrize("luks_uuid", ["", " "])
    def test_empty_luks_uuid(self, luks_uuid):
        """An empty LUKS UUID is rejected."""
        raw = json.dumps(
            {
                TARGET: {
                    "mapper_path": "/dev/mapper/crypt-a",
                    "luks_uuid": luks_uuid,
                }
            }
        )

        with pytest.raises(ValueError):
            parse_device_results(raw)

    def test_duplicate_target(self):
        """The same target cannot appear twice in the result map."""
        raw = (
            '{"/dev/disk/by-id/device-a": '
            '{"mapper_path": "/dev/mapper/crypt-a", "luks_uuid": "uuid-a"}, '
            '"/dev/disk/by-id/device-a": '
            '{"mapper_path": "/dev/mapper/crypt-b", "luks_uuid": "uuid-b"}}'
        )

        with pytest.raises(ValueError):
            parse_device_results(raw)


class TestEncryptedDeviceRequires:
    """Test the Vaultlocker side of the relation library."""

    def test_requests_changed_reads_unit_requests(self):
        """A unit relation change exposes its validated requests."""
        raw = json.dumps({TARGET: {}})
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="principal",
            remote_units_data={
                0: {
                    "device_requests": raw,
                }
            },
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _RequirerCharm,
            meta=_REQUIRER_METADATA,
        )

        state_out = context.run(
            context.on.relation_changed(relation, remote_unit=0),
            state,
        )

        assert state_out.unit_status == testing.ActiveStatus("Received 1 device requests")

    def test_missing_request_field_returns_no_requests(self):
        """A unit that has not written requests exposes an empty list."""
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="principal",
            remote_units_data={0: {}},
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _RequirerCharm,
            meta=_REQUIRER_METADATA,
        )

        state_out = context.run(
            context.on.relation_changed(relation, remote_unit=0),
            state,
        )

        assert state_out.unit_status == testing.ActiveStatus("Received 0 device requests")

    def test_set_device_results_writes_unit_data(self):
        """Results are written to the Vaultlocker unit databag."""
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="principal",
            remote_units_data={0: {}},
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _RequirerCharm,
            meta=_REQUIRER_METADATA,
        )

        state_out = context.run(
            context.on.config_changed(),
            state,
        )

        relation_out = state_out.get_relation(relation.id)
        assert json.loads(relation_out.local_unit_data["device_results"]) == {
            TARGET: {
                "mapper_path": "/dev/mapper/crypt-a",
                "luks_uuid": "uuid-a",
            }
        }


class TestEncryptedDeviceProvides:
    """Test the principal side of the relation library."""

    def test_results_changed_reads_unit_results(self):
        """A unit relation change has validated results."""
        raw = json.dumps(
            {
                TARGET: {
                    "mapper_path": "/dev/mapper/crypt-a",
                    "luks_uuid": "uuid-a",
                }
            }
        )
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="vaultlocker",
            remote_units_data={
                0: {
                    "device_results": raw,
                }
            },
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _ProviderCharm,
            meta=_PROVIDER_METADATA,
        )

        state_out = context.run(
            context.on.relation_changed(relation, remote_unit=0),
            state,
        )

        assert state_out.unit_status == testing.ActiveStatus("Received 1 device results")

    def test_missing_result_field_returns_no_results(self):
        """A unit that has not written results exposes an empty list."""
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="vaultlocker",
            remote_units_data={0: {}},
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _ProviderCharm,
            meta=_PROVIDER_METADATA,
        )

        state_out = context.run(
            context.on.relation_changed(relation, remote_unit=0),
            state,
        )

        assert state_out.unit_status == testing.ActiveStatus("Received 0 device results")

    def test_set_device_requests_writes_unit_data(self):
        """Requests are written to the principal unit databag."""
        relation = testing.Relation(
            endpoint="encrypted-device",
            remote_app_name="vaultlocker",
            remote_units_data={0: {}},
        )
        state = testing.State(relations=[relation])
        context = testing.Context(
            _ProviderCharm,
            meta=_PROVIDER_METADATA,
        )

        state_out = context.run(
            context.on.config_changed(),
            state,
        )

        relation_out = state_out.get_relation(relation.id)
        assert json.loads(relation_out.local_unit_data["device_requests"]) == {TARGET: {}}
