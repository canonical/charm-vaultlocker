# Integration tests

These tests exercise the `vaultlocker` subordinate charm with a test principal
charm and a `vault-kv` integration.

## Prerequisites

- A Juju controller with an LXD cloud.
- Charmcraft and tox-uv.
- A built Vaultlocker charm in the repository root, or `CHARM_PATH` set to
  its path.

## Configuration

- `CHARM_PATH` (optional): path to the built charm.
- `VAULTLOCKER_SNAP_CHANNEL` (optional): snap channel to use. If unset,
  the charm uses its configured default.

## Running

```bash
charmcraft pack
VAULTLOCKER_SNAP_CHANNEL=latest/edge tox -e integration
```
