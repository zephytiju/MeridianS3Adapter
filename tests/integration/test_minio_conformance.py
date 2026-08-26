# SPDX-License-Identifier: Apache-2.0
"""Real S3-compatible evidence against a disposable, digest-pinned MinIO server."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import boto3
import pytest
from meridian_storage.object_common import (
    FactoryPayloadSource,
    ObjectCatalogProvider,
    ObjectNotFound,
    PayloadRegistry,
    RetentionDenied,
    run_object_conformance,
    transfer_payload,
)
from meridian_storage.semantics import JsonValue, sha256_fingerprint

from meridian_storage.adapters.s3 import (
    S3Config,
    S3HealthProbe,
    S3ObjectAdapter,
    S3Transport,
    __version__,
)

pytestmark = pytest.mark.integration


def _required_environment() -> tuple[str, str, str]:
    endpoint = os.environ.get("MERIDIAN_S3_ENDPOINT")
    access = os.environ.get("MERIDIAN_S3_ACCESS_KEY")
    secret = os.environ.get("MERIDIAN_S3_SECRET_KEY")
    if not endpoint or not access or not secret:
        pytest.skip("disposable S3 endpoint credentials were not provided")
    return endpoint, access, secret


def _client(endpoint: str, access: str, secret: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=access,
        aws_secret_access_key=secret,
    )


def _execute(
    adapter: S3ObjectAdapter,
    payloads: PayloadRegistry,
    expression: object,
) -> dict[str, object]:
    provider = ObjectCatalogProvider()
    return dict(adapter.execute(provider.normalize(expression), payloads))  # type: ignore[arg-type]


def _put(
    adapter: S3ObjectAdapter,
    payloads: PayloadRegistry,
    *,
    resource: str,
    object_id: str,
    payload: bytes,
    user_metadata: dict[str, str],
    retention: dict[str, object] | None = None,
) -> dict[str, object]:
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    reference = payloads.register(
        FactoryPayloadSource(lambda: BytesIO(payload), replayable=True),
        expected_digest=digest,
    )
    surface = ObjectCatalogProvider().create_surface()
    result = _execute(
        adapter,
        payloads,
        surface.put(
            resource=resource,
            object_id=object_id,
            payload=reference,
            media_type="application/octet-stream",
            expected_digest=digest,
            expected_length=None,
            user_metadata=user_metadata,
            retention=retention,
            create_only=True,
        ),
    )
    metadata = result["metadata"]
    assert isinstance(metadata, dict)
    return metadata


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_real_minio_conformance_and_deterministic_evidence() -> None:
    endpoint, access, secret = _required_environment()
    client = _client(endpoint, access, secret)
    normal_bucket = "meridian-s3-conformance"
    locked_bucket = "meridian-s3-retention"
    client.create_bucket(Bucket=normal_bucket)
    client.put_bucket_versioning(
        Bucket=normal_bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    normal_config = S3Config(
        bucket=normal_bucket,
        prefix="object-v1",
        endpoint_url=endpoint,
        allow_insecure_http=endpoint.startswith("http://"),
        multipart_threshold_bytes=5 * 1024 * 1024,
        multipart_part_bytes=5 * 1024 * 1024,
        spool_memory_bytes=64 * 1024,
        integrity_chunk_bytes=64 * 1024,
        max_range_bytes=8 * 1024 * 1024,
        require_versioning=True,
    )
    normal_transport = S3Transport(client, normal_config)
    normal_payloads = PayloadRegistry()
    normal_adapter = S3ObjectAdapter(
        normal_transport,
        normal_config,
        payloads=normal_payloads,
    )

    common_report = run_object_conformance(normal_adapter)
    common_report.require_success()
    normal_probe, normal_probe_evidence = S3HealthProbe(normal_transport, normal_config).run()
    assert normal_probe_evidence.versioning_enabled

    payload = b"m" * (5 * 1024 * 1024) + b"multipart-range-tail"
    metadata = _put(
        normal_adapter,
        normal_payloads,
        resource="object:minio.objects",
        object_id="media/large.bin",
        payload=payload,
        user_metadata={"display-name": "真实对象", "owner": "Meridian"},
    )
    reference = cast(dict[str, object], metadata["objectRef"])
    digest = cast(str, metadata["digest"])
    resource = (
        ObjectCatalogProvider()
        .normalize(
            ObjectCatalogProvider()
            .create_surface()
            .stat(resource="object:minio.objects", reference=reference)
        )
        .resources[0]
    )
    blob_key = normal_adapter.layout.blob_key(
        resource,
        cast(str, reference["objectId"]),
        digest,
    )
    physical = client.head_object(Bucket=normal_bucket, Key=blob_key)
    assert "-" in physical["ETag"]
    assert physical["Metadata"] == {
        "meridian-digest": digest.removeprefix("sha256:"),
        "meridian-format": "object-v1",
    }
    assert metadata["userMetadata"] == {
        "display-name": "真实对象",
        "owner": "Meridian",
    }

    surface = ObjectCatalogProvider().create_surface()
    selected_start = 65_530
    selected_end = 131_090
    ranged = _execute(
        normal_adapter,
        normal_payloads,
        surface.read_range(
            resource="object:minio.objects",
            reference=reference,
            byte_range={"start": selected_start, "end": selected_end},
        ),
    )
    range_sink = BytesIO()
    transfer_payload(ranged["payload"], normal_payloads, range_sink)  # type: ignore[arg-type]
    assert range_sink.getvalue() == payload[selected_start : selected_end + 1]

    fetched = _execute(
        normal_adapter,
        normal_payloads,
        surface.get(resource="object:minio.objects", reference=reference),
    )
    full_sink = BytesIO()
    identity = transfer_payload(fetched["payload"], normal_payloads, full_sink)  # type: ignore[arg-type]
    assert identity.digest == digest
    assert full_sink.getvalue() == payload
    with pytest.raises(ObjectNotFound):
        normal_transport.head("object-v1/does-not-exist")

    client.create_bucket(Bucket=locked_bucket, ObjectLockEnabledForBucket=True)
    locked_config = S3Config(
        bucket=locked_bucket,
        prefix="object-v1",
        endpoint_url=endpoint,
        allow_insecure_http=endpoint.startswith("http://"),
        object_lock_mode="COMPLIANCE",
        require_versioning=True,
        checksum_headers=True,
        spool_memory_bytes=64 * 1024,
        integrity_chunk_bytes=64 * 1024,
    )
    locked_transport = S3Transport(client, locked_config)
    locked_payloads = PayloadRegistry()
    locked_adapter = S3ObjectAdapter(
        locked_transport,
        locked_config,
        payloads=locked_payloads,
    )
    locked_probe, locked_probe_evidence = S3HealthProbe(locked_transport, locked_config).run()
    assert locked_probe_evidence.versioning_enabled
    assert locked_probe_evidence.object_lock_enabled
    retain_until = _timestamp(datetime.now(UTC) + timedelta(hours=1))
    locked_metadata = _put(
        locked_adapter,
        locked_payloads,
        resource="object:minio.locked",
        object_id="retained.bin",
        payload=b"provider-enforced-retention",
        user_metadata={"classification": "evidence"},
        retention={
            "retainUntil": retain_until,
            "policy": None,
            "requireEnforcement": True,
        },
    )
    locked_reference = cast(dict[str, object], locked_metadata["objectRef"])
    locked_resource = (
        ObjectCatalogProvider()
        .normalize(
            ObjectCatalogProvider()
            .create_surface()
            .stat(resource="object:minio.locked", reference=locked_reference)
        )
        .resources[0]
    )
    locked_digest = cast(str, locked_metadata["digest"])
    locked_blob_key = locked_adapter.layout.blob_key(
        locked_resource,
        cast(str, locked_reference["objectId"]),
        locked_digest,
    )
    locked_envelope = locked_adapter._read_envelope(
        locked_resource,
        cast(str, locked_reference["objectId"]),
        locked_digest,
    )
    locked_head = client.head_object(
        Bucket=locked_bucket,
        Key=locked_blob_key,
        VersionId=locked_envelope.blob_version_id,
    )
    assert locked_head["ObjectLockMode"] == "COMPLIANCE"
    assert locked_head["ObjectLockRetainUntilDate"] >= datetime.now(UTC)
    with pytest.raises(RetentionDenied):
        _execute(
            locked_adapter,
            locked_payloads,
            surface.delete(
                resource="object:minio.locked",
                reference=locked_reference,
                reason="must-remain-retained",
            ),
        )
    with pytest.raises(RetentionDenied):
        locked_transport.delete(
            locked_blob_key,
            version_id=locked_envelope.blob_version_id,
            retention_sensitive=True,
        )

    report: dict[str, JsonValue] = {
        "formatVersion": "meridian.s3-conformance-evidence.v1",
        "package": {"name": "meridian-storage-s3", "version": __version__},
        "engine": {
            "name": "MinIO",
            "release": os.environ.get("MERIDIAN_S3_ENGINE_RELEASE", "RELEASE.2025-04-22T22-12-26Z"),
            "imageDigest": os.environ.get("MERIDIAN_S3_ENGINE_DIGEST", "unknown"),
        },
        "objectCommon": cast(JsonValue, common_report.to_dict()),
        "checks": [
            {
                "name": "authenticated-health-and-versioning",
                "passed": normal_probe.evidence["versioning"] == "Enabled",
            },
            {"name": "multipart-upload", "passed": True},
            {"name": "verified-inclusive-range", "passed": True},
            {"name": "portable-metadata-mapping", "passed": True},
            {"name": "streaming-full-digest", "passed": True},
            {"name": "not-found-normalization", "passed": True},
            {
                "name": "object-lock-retention",
                "passed": locked_probe.evidence["objectLock"] == "enabled",
                "mode": "COMPLIANCE",
            },
            {"name": "retention-failure-normalization", "passed": True},
        ],
    }
    report["fingerprint"] = sha256_fingerprint(report)
    output = os.environ.get("MERIDIAN_S3_EVIDENCE_PATH")
    if output:
        Path(output).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
