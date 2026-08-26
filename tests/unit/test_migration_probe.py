# SPDX-License-Identifier: Apache-2.0
"""Authenticated probe and externally orchestrated migration hook tests."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from meridian_storage.object_common import (
    ConditionalConflict,
    ObjectCapabilityMismatch,
    ObjectInvalidRequest,
    ObjectUnavailable,
)
from moto import mock_aws

from meridian_storage import ResourceRef
from meridian_storage.adapters.s3 import S3Config, S3Transport
from meridian_storage.adapters.s3.layout import S3Layout
from meridian_storage.adapters.s3.migration import (
    S3MigrationHooks,
    S3MigrationPlan,
    S3MigrationResult,
)
from meridian_storage.adapters.s3.probe import S3HealthProbe, S3ProbeEvidence


class _ProbeTransport:
    def __init__(self, *, versioning: str = "Disabled", object_lock: bool = False) -> None:
        self.versioning = versioning
        self.object_lock = object_lock
        self.head_calls = 0

    def head_bucket(self) -> None:
        self.head_calls += 1

    def versioning_status(self) -> str:
        return self.versioning

    def object_lock_enabled(self) -> bool:
        return self.object_lock


def test_probe_is_minimal_by_default_and_selectively_advertises_verified_features() -> None:
    plain_transport = _ProbeTransport()
    probe, evidence = S3HealthProbe(plain_transport, S3Config(bucket="valid-bucket")).run()  # type: ignore[arg-type]
    assert evidence == S3ProbeEvidence("NotProbed", False)
    assert not evidence.versioning_enabled
    assert probe.evidence["versioning"] == "NotProbed"
    assert plain_transport.head_calls == 1

    verified_transport = _ProbeTransport(versioning="Enabled", object_lock=True)
    locked = S3Config(
        bucket="valid-bucket",
        require_versioning=True,
        object_lock_mode="compliance",
        checksum_headers=True,
    )
    locked_probe, locked_evidence = S3HealthProbe(
        verified_transport,
        locked,
        signed_references=True,  # type: ignore[arg-type]
    ).run()
    assert locked_evidence.versioning_enabled
    assert locked_probe.evidence == {
        "authenticated": "true",
        "bucketAccess": "verified",
        "checksumHeaders": "true",
        "objectLock": "enabled",
        "versioning": "Enabled",
    }


def test_probe_fails_closed_for_unverified_required_features() -> None:
    versioned = S3Config(bucket="valid-bucket", require_versioning=True)
    with pytest.raises(ObjectUnavailable, match="versioning"):
        S3HealthProbe(_ProbeTransport(), versioned).run()  # type: ignore[arg-type]
    locked = S3Config(bucket="valid-bucket", object_lock_mode="governance")
    with pytest.raises(ObjectCapabilityMismatch, match="not verified") as captured:
        S3HealthProbe(
            _ProbeTransport(versioning="Enabled", object_lock=False),
            locked,  # type: ignore[arg-type]
        ).run()
    assert captured.value.adapter_provenance["objectLockVerified"] == "false"


@pytest.mark.parametrize(
    "plan",
    [
        S3MigrationPlan,
    ],
)
def test_migration_plan_is_forward_only_and_object_scoped(plan: Any) -> None:
    resource = ResourceRef("object", "test", "objects")
    invalid = (
        {"current_revision": 1, "target_revision": 1, "resources": (resource,)},
        {"current_revision": True, "target_revision": 1, "resources": (resource,)},
        {"current_revision": 0, "target_revision": 2, "resources": (resource,)},
        {"current_revision": 0, "target_revision": 1, "resources": ()},
        {"current_revision": 0, "target_revision": 1, "resources": (resource, resource)},
        {
            "current_revision": 0,
            "target_revision": 1,
            "resources": (ResourceRef("cache", "test", "objects"),),
        },
    )
    for values in invalid:
        with pytest.raises(ObjectInvalidRequest):
            plan(actions=("record",), **values)


def test_migration_plan_and_result_are_deterministic() -> None:
    first = ResourceRef("object", "zeta", "objects")
    second = ResourceRef("object", "alpha", "objects")
    plan = S3MigrationPlan(0, 1, (first, second), ("validate", "record"))
    assert plan.resources == (second, first)
    assert plan.to_dict()["fingerprint"] == plan.fingerprint
    assert plan.to_dict(include_fingerprint=False)["formatVersion"] == (
        "meridian.s3-migration-plan.v1"
    )
    assert S3MigrationResult(plan.fingerprint, True).to_dict() == {
        "formatVersion": "meridian.s3-migration-result.v1",
        "planFingerprint": plan.fingerprint,
        "applied": True,
    }


def test_migration_apply_is_idempotent_and_detects_plan_conflict() -> None:
    with mock_aws():
        client = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="test-access",
            aws_secret_access_key="test-secret",
        )
        client.create_bucket(Bucket="meridian-test-bucket")
        config = S3Config(bucket="meridian-test-bucket", prefix="migrations")
        transport = S3Transport(client, config)
        hooks = S3MigrationHooks(transport, S3Layout(config))
        resources = (ResourceRef("object", "test", "objects"),)
        plan = hooks.plan(current_revision=0, target_revision=1, resources=resources)
        first = hooks.apply(plan)
        second = hooks.apply(plan)
        assert first == S3MigrationResult(plan.fingerprint, True)
        assert second == S3MigrationResult(plan.fingerprint, False)
        key = S3Layout(config).migration_key(1)
        transport.put_json(
            key,
            {"formatVersion": "meridian.s3-migration-record.v1", "plan": {"changed": True}},
        )
        with pytest.raises(ConditionalConflict, match="different migration plan"):
            hooks.apply(plan)
        with pytest.raises(TypeError, match="S3MigrationPlan"):
            hooks.apply(object())  # type: ignore[arg-type]
