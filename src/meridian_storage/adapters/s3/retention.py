# SPDX-License-Identifier: Apache-2.0
"""Portable retention intent and optional S3 Object Lock mapping."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from meridian_storage.object_common import RetentionDenied, RetentionRequest
from meridian_storage.semantics import JsonValue

from .config import S3Config


@dataclass(frozen=True, slots=True)
class RetentionRecord:
    retain_until: str | None
    policy: str | None
    require_enforcement: bool
    provider_enforced: bool
    object_lock_mode: str | None

    @classmethod
    def from_request(
        cls,
        request: RetentionRequest | None,
        config: S3Config,
    ) -> RetentionRecord | None:
        if request is None:
            return None
        if request.require_enforcement and not config.retention_enforcement:
            raise RetentionDenied(
                "retention enforcement was required but is unavailable",
                adapter_provenance={"adapterId": "s3", "retentionEnforcement": "false"},
            )
        return cls(
            retain_until=cast(str | None, request.retain_until),
            policy=request.policy,
            require_enforcement=request.require_enforcement,
            provider_enforced=config.retention_enforcement and request.retain_until is not None,
            object_lock_mode=(
                config.object_lock_mode
                if config.retention_enforcement and request.retain_until is not None
                else None
            ),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object] | None) -> RetentionRecord | None:
        if value is None:
            return None
        required = {
            "retainUntil",
            "policy",
            "requireEnforcement",
            "providerEnforced",
            "objectLockMode",
        }
        if set(value) != required:
            raise ValueError("stored retention record has unknown or missing fields")
        return cls(
            retain_until=cast(str | None, value["retainUntil"]),
            policy=cast(str | None, value["policy"]),
            require_enforcement=cast(bool, value["requireEnforcement"]),
            provider_enforced=cast(bool, value["providerEnforced"]),
            object_lock_mode=cast(str | None, value["objectLockMode"]),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "retainUntil": self.retain_until,
            "policy": self.policy,
            "requireEnforcement": self.require_enforcement,
            "providerEnforced": self.provider_enforced,
            "objectLockMode": self.object_lock_mode,
        }

    def object_lock_arguments(self) -> dict[str, object]:
        if not self.provider_enforced or self.retain_until is None:
            return {}
        deadline = datetime.strptime(self.retain_until, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        return {
            "ObjectLockMode": self.object_lock_mode,
            "ObjectLockRetainUntilDate": deadline,
        }

    def require_delete_allowed(self, *, now: datetime | None = None) -> None:
        if self.retain_until is None:
            raise RetentionDenied("logical retention policy does not permit deletion")
        selected = datetime.now(UTC) if now is None else now
        if selected.tzinfo is None or selected.utcoffset() is None:
            raise ValueError("retention deletion check must be timezone-aware")
        deadline = datetime.strptime(self.retain_until, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        if selected.astimezone(UTC) < deadline:
            raise RetentionDenied()


def parse_retention_request(value: object) -> RetentionRequest | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError("retention must be an object or null")
    return RetentionRequest.from_mapping(cast(Mapping[str, object], value))


__all__ = ["RetentionRecord", "parse_retention_request"]
