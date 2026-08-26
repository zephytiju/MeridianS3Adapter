# SPDX-License-Identifier: Apache-2.0
"""Portable retention and Object Lock mapping tests."""

from datetime import UTC, datetime, timedelta

import pytest
from meridian_storage.object_common import RetentionDenied, RetentionRequest

from meridian_storage.adapters.s3 import S3Config
from meridian_storage.adapters.s3.retention import RetentionRecord


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_enforcement_fails_closed_when_bucket_profile_does_not_advertise_it() -> None:
    request = RetentionRequest(
        retain_until=_timestamp(datetime.now(UTC) + timedelta(days=1)),
        require_enforcement=True,
    )
    with pytest.raises(RetentionDenied):
        RetentionRecord.from_request(request, S3Config(bucket="valid-bucket"))


def test_object_lock_mapping_and_delete_deadline() -> None:
    deadline = datetime.now(UTC) + timedelta(days=1)
    record = RetentionRecord.from_request(
        RetentionRequest(retain_until=_timestamp(deadline), require_enforcement=True),
        S3Config(bucket="valid-bucket", object_lock_mode="governance"),
    )
    assert record is not None
    assert record.provider_enforced
    assert record.object_lock_arguments()["ObjectLockMode"] == "GOVERNANCE"
    with pytest.raises(RetentionDenied):
        record.require_delete_allowed(now=deadline - timedelta(seconds=1))
    record.require_delete_allowed(now=deadline + timedelta(seconds=1))
    assert RetentionRecord.from_mapping(record.to_dict()) == record


def test_logical_policy_without_deadline_denies_delete() -> None:
    record = RetentionRecord.from_request(
        RetentionRequest(policy="legal-hold", require_enforcement=False),
        S3Config(bucket="valid-bucket"),
    )
    assert record is not None
    with pytest.raises(RetentionDenied):
        record.require_delete_allowed()
