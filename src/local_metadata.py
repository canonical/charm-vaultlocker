# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Store progress for devices managed by the vaultlocker charm.

This lets the charm remember what happened to each device between hook runs.
Only non-secret information is stored here.
"""

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILE_NAME = "state.json"

REQUEST_TYPE_ENCRYPT = "encrypt"
REQUEST_TYPE_ENROLL = "enroll"


@dataclass
class DeviceFailure:
    """The latest failure recorded for a device."""

    message: str
    timestamp: str

    def to_dict(self) -> dict:
        """Return the JSON-serialisable representation."""
        return {
            "message": self.message,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceFailure":
        """Build a failure from its JSON representation."""
        return cls(
            message=data["message"],
            timestamp=data["timestamp"],
        )


@dataclass
class DeviceState:
    """Saved state for a device managed by vaultlocker."""

    request_type: str
    completed: bool = False
    luks_uuid: str | None = None
    mapper_path: str | None = None
    last_failure: DeviceFailure | None = None

    def to_dict(self) -> dict:
        """Return the JSON-serialisable representation."""
        return {
            "request_type": self.request_type,
            "completed": self.completed,
            "luks_uuid": self.luks_uuid,
            "mapper_path": self.mapper_path,
            "last_failure": (
                self.last_failure.to_dict() if self.last_failure is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceState":
        """Build device state from its JSON representation."""
        failure = data.get("last_failure")
        return cls(
            request_type=data["request_type"],
            completed=bool(data.get("completed", False)),
            luks_uuid=data.get("luks_uuid"),
            mapper_path=data.get("mapper_path"),
            last_failure=DeviceFailure.from_dict(failure) if failure else None,
        )


class LocalMetadataStore:
    """Read and write saved device state."""

    def __init__(self, path: Path):
        """Store state in ``path`` (a JSON file)."""
        self.path = path

    def get(self, target: str) -> DeviceState | None:
        """Return saved state for ``target``, if it exists."""
        return self._read().get(target)

    def all(self) -> dict[str, DeviceState]:
        """Return the saved state for every managed device."""
        return self._read()

    def set(self, target: str, state: DeviceState) -> None:
        """Save ``state`` for ``target``."""
        states = self._read()
        states[target] = state
        self._write(states)

    def record_failure(
        self,
        target: str,
        request_type: str,
        message: str,
    ) -> DeviceState:
        """Save the latest failure for ``target``."""
        state = self.get(target) or DeviceState(request_type=request_type)
        state.last_failure = DeviceFailure(
            message=message,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.set(target, state)
        return state

    def mark_completed(
        self,
        target: str,
        request_type: str,
        luks_uuid: str,
        mapper_path: str,
    ) -> DeviceState:
        """Save that ``target`` has completed and return the updated state."""
        state = self.get(target) or DeviceState(request_type=request_type)
        state.request_type = request_type
        state.completed = True
        state.luks_uuid = luks_uuid
        state.mapper_path = mapper_path
        state.last_failure = None
        self.set(target, state)
        return state

    def _read(self) -> dict[str, DeviceState]:
        """Read all saved device state from disk."""
        if not self.path.exists():
            return {}

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            logger.warning("Unable to read vaultlocker state file %s: %s", self.path, error)
            return {}

        return {target: DeviceState.from_dict(data) for target, data in raw.items()}

    def _write(self, states: dict[str, DeviceState]) -> None:
        """Atomically replace the state file with ``states``."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {target: state.to_dict() for target, state in states.items()}
        content = json.dumps(payload, indent=2, sort_keys=True)

        fd, temporary_name = tempfile.mkstemp(dir=self.path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                os.fchmod(temp_file.fileno(), 0o600)
                temp_file.write(content)
            os.replace(temporary_path, self.path)
        finally:
            temporary_path.unlink(missing_ok=True)
