Library for the encrypted-device relation.

The Vaultlocker subordinate charm requires this relation. A principal charm provides the
relation to request encryption or enrolment of block devices on the same
machine.

## Device requests

Each principal unit writes `device_requests` to its unit databag. The value is
a JSON object keyed by stable device paths.

An empty object requests fresh encryption of that device:

```json
{
    "/dev/disk/by-id/device-a": {}
}
```

To enrol an existing LUKS device, the request includes the ID of a Juju secret
containing its current passphrase:

```json
{
    "/dev/disk/by-id/device-b": {
        "existing_key_secret_id": "secret:existing-key"
    }
}
```

Vaultlocker must be granted access to any secret referenced by
`existing_key_secret_id`. The passphrase itself must not be written to relation
data.

## Device results

After successfully provisioning a device, Vaultlocker writes
`device_results` to its unit databag. The result uses the same device path as
the corresponding request:

```json
{
    "/dev/disk/by-id/device-a": {
        "mapper_path": "/dev/mapper/crypt-a1b2c3d4",
        "luks_uuid": "a1b2c3d4"
    }
}
```

Only successful results are written to relation data.
