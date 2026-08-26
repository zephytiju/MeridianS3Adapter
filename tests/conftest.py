# SPDX-License-Identifier: Apache-2.0
"""Shared disposable S3 fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import boto3
import pytest
from meridian_storage.object_common import PayloadRegistry
from moto import mock_aws

from meridian_storage.adapters.s3 import S3Config, S3ObjectAdapter, S3Transport


@dataclass(slots=True)
class S3Fixture:
    adapter: S3ObjectAdapter
    payloads: PayloadRegistry
    client: Any


@pytest.fixture
def s3_fixture() -> Iterator[S3Fixture]:
    with mock_aws():
        client = boto3.client(
            "s3",
            region_name="us-east-1",
            aws_access_key_id="test-access",
            aws_secret_access_key="test-secret",
        )
        client.create_bucket(Bucket="meridian-test-bucket")
        client.put_bucket_versioning(
            Bucket="meridian-test-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        config = S3Config(
            bucket="meridian-test-bucket",
            prefix="tests",
            multipart_threshold_bytes=5 * 1024 * 1024,
            multipart_part_bytes=5 * 1024 * 1024,
            spool_memory_bytes=64 * 1024,
            integrity_chunk_bytes=64 * 1024,
            max_range_bytes=8 * 1024 * 1024,
        )
        payloads = PayloadRegistry()
        adapter = S3ObjectAdapter(S3Transport(client, config), config, payloads=payloads)
        yield S3Fixture(adapter, payloads, client)
