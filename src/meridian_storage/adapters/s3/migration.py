# SPDX-License-Identifier: Apache-2.0
"""Forward-only adapter metadata hooks invoked by an IaC-owned migration job."""

from __future__ import annotations

from dataclasses import dataclass

from meridian_storage.object_common import ConditionalConflict, ObjectInvalidRequest
from meridian_storage.semantics import JsonValue, sha256_fingerprint

from meridian_storage import ResourceRef

from .layout import S3Layout
from .transport import S3Transport

S3_METADATA_REVISION = 1


@dataclass(frozen=True, slots=True)
class S3MigrationPlan:
    current_revision: int
    target_revision: int
    resources: tuple[ResourceRef, ...]
    actions: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            isinstance(self.current_revision, bool)
            or isinstance(self.target_revision, bool)
            or not isinstance(self.current_revision, int)
            or not isinstance(self.target_revision, int)
            or self.current_revision < 0
            or self.target_revision <= self.current_revision
        ):
            raise ObjectInvalidRequest("S3 migrations must be explicit and forward-only")
        if self.target_revision != S3_METADATA_REVISION:
            raise ObjectInvalidRequest("unsupported S3 adapter metadata revision")
        normalized = tuple(sorted(ResourceRef.parse(item) for item in self.resources))
        if not normalized or len(set(normalized)) != len(normalized):
            raise ObjectInvalidRequest("S3 migration requires unique Object Resources")
        if any(item.catalog != "object" for item in normalized):
            raise ObjectInvalidRequest("S3 migration accepts only Object Resources")
        object.__setattr__(self, "resources", normalized)

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict(include_fingerprint=False))

    def to_dict(self, *, include_fingerprint: bool = True) -> dict[str, JsonValue]:
        value: dict[str, JsonValue] = {
            "formatVersion": "meridian.s3-migration-plan.v1",
            "currentRevision": self.current_revision,
            "targetRevision": self.target_revision,
            "resources": [item.to_dict() for item in self.resources],
            "actions": list(self.actions),
        }
        if include_fingerprint:
            value["fingerprint"] = self.fingerprint
        return value


@dataclass(frozen=True, slots=True)
class S3MigrationResult:
    plan_fingerprint: str
    applied: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "formatVersion": "meridian.s3-migration-result.v1",
            "planFingerprint": self.plan_fingerprint,
            "applied": self.applied,
        }


class S3MigrationHooks:
    """Validate and record adapter metadata changes without provisioning or lifecycle authority."""

    def __init__(self, transport: S3Transport, layout: S3Layout) -> None:
        self._transport = transport
        self._layout = layout

    def plan(
        self,
        *,
        current_revision: int,
        target_revision: int,
        resources: tuple[ResourceRef, ...],
    ) -> S3MigrationPlan:
        return S3MigrationPlan(
            current_revision=current_revision,
            target_revision=target_revision,
            resources=resources,
            actions=(
                "validate-authenticated-bucket",
                "validate-object-v1-prefix",
                "record-metadata-revision",
            ),
        )

    def apply(self, plan: S3MigrationPlan) -> S3MigrationResult:
        if not isinstance(plan, S3MigrationPlan):
            raise TypeError("S3 migration apply requires an S3MigrationPlan")
        self._transport.head_bucket()
        document = {
            "formatVersion": "meridian.s3-migration-record.v1",
            "plan": plan.to_dict(),
        }
        key = self._layout.migration_key(plan.target_revision)
        try:
            self._transport.put_json(key, document, create_only=True)
            applied = True
        except ConditionalConflict:
            if self._transport.read_json(key) != document:
                raise ConditionalConflict(
                    "S3 metadata revision has a different migration plan"
                ) from None
            applied = False
        return S3MigrationResult(plan.fingerprint, applied)


__all__ = [
    "S3_METADATA_REVISION",
    "S3MigrationHooks",
    "S3MigrationPlan",
    "S3MigrationResult",
]
