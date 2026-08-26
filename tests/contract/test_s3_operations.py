# SPDX-License-Identifier: Apache-2.0
"""Provider-specific operation behavior through Object Common Expressions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any

import pytest
from meridian_storage.object_common import (
    ConditionalConflict,
    DigestMismatch,
    FactoryPayloadSource,
    HmacSha256Key,
    ImmutableObjectConflict,
    ObjectAuthorizationFailed,
    ObjectCatalogProvider,
    ObjectInvalidRequest,
    ObjectNotFound,
    RetentionDenied,
    sign_object_reference,
    transfer_payload,
)

from meridian_storage.adapters.s3 import S3ObjectAdapter


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _provider() -> ObjectCatalogProvider:
    return ObjectCatalogProvider()


def _execute(fixture: Any, expression: object) -> dict[str, object]:
    provider = _provider()
    return dict(fixture.adapter.execute(provider.normalize(expression), fixture.payloads))


def _put(
    fixture: Any,
    payload: bytes,
    *,
    resource: str = "object:tests.objects",
    object_id: str = "item.bin",
    create_only: bool = True,
    metadata: dict[str, str] | None = None,
    immutability: dict[str, object] | None = None,
    retention: dict[str, object] | None = None,
    creation_context: dict[str, object] | None = None,
    provenance: dict[str, object] | None = None,
    expected_length: int | None = None,
) -> dict[str, object]:
    provider = _provider()
    surface = provider.create_surface()
    digest = _digest(payload)
    reference = fixture.payloads.register(
        FactoryPayloadSource(lambda: BytesIO(payload), replayable=True),
        expected_digest=digest,
        expected_length=expected_length,
    )
    expression = surface.put(
        resource=resource,
        object_id=object_id,
        payload=reference,
        media_type="application/octet-stream",
        expected_digest=digest,
        expected_length=expected_length,
        user_metadata=metadata or {},
        creation_context=creation_context or {},
        provenance=provenance or {},
        immutability=immutability,
        retention=retention,
        create_only=create_only,
    )
    return dict(fixture.adapter.execute(provider.normalize(expression), fixture.payloads))


def _metadata(result: dict[str, object]) -> dict[str, object]:
    value = result["metadata"]
    assert isinstance(value, dict)
    return value


def test_registry_operations_are_idempotent_and_conflict_on_changed_definition(
    s3_fixture: Any,
) -> None:
    provider = _provider()
    surface = provider.create_surface()
    schema = surface.publish_schema(
        namespace="tests", name="metadata", version="1.0.0", definition={"type": "object"}
    )
    first = s3_fixture.adapter.execute(provider.normalize(schema), s3_fixture.payloads)
    second = s3_fixture.adapter.execute(provider.normalize(schema), s3_fixture.payloads)
    assert first["created"] is True
    assert second["created"] is False
    changed = surface.publish_schema(
        namespace="tests", name="metadata", version="1.0.0", definition={"type": "string"}
    )
    with pytest.raises(ConditionalConflict):
        s3_fixture.adapter.execute(provider.normalize(changed), s3_fixture.payloads)

    resource = surface.create_resource(
        namespace="tests",
        name="objects",
        profile={
            "kind": "media",
            "profile": "media",
            "mutability": "mutable",
            "rangeReads": True,
            "conditionalCreate": True,
            "boundedPrefixList": True,
            "metadata": {},
        },
    )
    created = s3_fixture.adapter.execute(provider.normalize(resource), s3_fixture.payloads)
    repeated = s3_fixture.adapter.execute(provider.normalize(resource), s3_fixture.payloads)
    assert created["created"] is True
    assert repeated["created"] is False


def test_metadata_round_trip_idempotence_and_immutable_conflict(s3_fixture: Any) -> None:
    payload = b"provider-neutral bytes"
    first = _put(
        s3_fixture,
        payload,
        create_only=False,
        metadata={"display-name": "测试", "owner": "Meridian"},
    )
    repeated = _put(
        s3_fixture,
        payload,
        create_only=False,
        metadata={"display-name": "测试", "owner": "Meridian"},
    )
    assert repeated == first
    assert _metadata(first)["userMetadata"] == {
        "display-name": "测试",
        "owner": "Meridian",
    }
    with pytest.raises(ConditionalConflict):
        _put(
            s3_fixture,
            payload,
            create_only=False,
            metadata={"owner": "different"},
        )
    with pytest.raises(ImmutableObjectConflict):
        _put(s3_fixture, b"replacement", create_only=False)
    with pytest.raises(ConditionalConflict, match="immutable metadata"):
        _put(
            s3_fixture,
            payload,
            create_only=False,
            metadata={"display-name": "测试", "owner": "Meridian"},
            provenance={"source": "different"},
        )
    with pytest.raises(ConditionalConflict, match="immutable metadata"):
        _put(
            s3_fixture,
            payload,
            create_only=False,
            metadata={"display-name": "测试", "owner": "Meridian"},
            creation_context={"tenant": "different"},
        )
    with pytest.raises(ConditionalConflict, match="immutable metadata"):
        _put(
            s3_fixture,
            payload,
            create_only=False,
            metadata={"display-name": "测试", "owner": "Meridian"},
            retention={
                "retainUntil": _timestamp(datetime.now(UTC) + timedelta(hours=1)),
                "policy": None,
                "requireEnforcement": False,
            },
        )
    with pytest.raises(ObjectInvalidRequest, match="reserved"):
        _put(
            s3_fixture,
            b"must-not-upload",
            object_id="reserved-provenance",
            provenance={"meridian.adapter": {"spoofed": True}},
        )


def test_mutable_versions_exact_read_and_delete_restores_previous_pointer(s3_fixture: Any) -> None:
    provider = _provider()
    surface = provider.create_surface()
    create = surface.create_resource(
        namespace="mutable",
        name="objects",
        profile={
            "kind": "object",
            "profile": "object",
            "mutability": "mutable",
            "rangeReads": True,
            "conditionalCreate": True,
            "boundedPrefixList": True,
            "metadata": {},
        },
    )
    s3_fixture.adapter.execute(provider.normalize(create), s3_fixture.payloads)
    first = _metadata(
        _put(
            s3_fixture,
            b"version-one",
            resource="object:mutable.objects",
            object_id="channel",
            create_only=False,
        )
    )
    second = _metadata(
        _put(
            s3_fixture,
            b"version-two",
            resource="object:mutable.objects",
            object_id="channel",
            create_only=False,
        )
    )
    stable = _execute(
        s3_fixture,
        surface.stat(
            resource="object:mutable.objects",
            reference={"resourceRef": first["objectRef"]["resourceRef"], "objectId": "channel"},
        ),
    )
    assert _metadata(stable)["digest"] == second["digest"]
    exact_first = _execute(
        s3_fixture,
        surface.stat(resource="object:mutable.objects", reference=first["objectRef"]),
    )
    assert _metadata(exact_first)["digest"] == first["digest"]
    deleted = _execute(
        s3_fixture,
        surface.delete(
            resource="object:mutable.objects",
            reference=second["objectRef"],
            reason="remove-current-version",
        ),
    )
    assert deleted == {"deleted": True}
    restored = _execute(
        s3_fixture,
        surface.stat(
            resource="object:mutable.objects",
            reference={"resourceRef": first["objectRef"]["resourceRef"], "objectId": "channel"},
        ),
    )
    assert _metadata(restored)["digest"] == first["digest"]


def test_multipart_unknown_length_and_range_integrity(s3_fixture: Any) -> None:
    payload = b"a" * (5 * 1024 * 1024) + b"range-tail"
    metadata = _metadata(
        _put(
            s3_fixture,
            payload,
            object_id="large.bin",
            expected_length=None,
        )
    )
    reference = metadata["objectRef"]
    assert isinstance(reference, dict)
    blob_key = s3_fixture.adapter.layout.blob_key(
        _provider()
        .normalize(
            _provider().create_surface().stat(resource="object:tests.objects", reference=reference)
        )
        .resources[0],
        "large.bin",
        str(metadata["digest"]),
    )
    head = s3_fixture.client.head_object(Bucket="meridian-test-bucket", Key=blob_key)
    assert "-" in head["ETag"]

    surface = _provider().create_surface()
    result = _execute(
        s3_fixture,
        surface.read_range(
            resource="object:tests.objects",
            reference=reference,
            byte_range={"suffixLength": 10},
        ),
    )
    sink = BytesIO()
    transfer_payload(result["payload"], s3_fixture.payloads, sink)
    assert sink.getvalue() == payload[-10:]

    envelope_key = s3_fixture.adapter.layout.reference_key(
        _provider()
        .normalize(surface.stat(resource="object:tests.objects", reference=reference))
        .resources[0],
        "large.bin",
        str(metadata["digest"]),
    )
    envelope = dict(s3_fixture.adapter.transport.read_json(envelope_key))
    integrity = dict(envelope["integrity"])
    integrity["chunkDigests"] = ["sha256:" + "0" * 64, *integrity["chunkDigests"][1:]]
    envelope["integrity"] = integrity
    s3_fixture.adapter.transport.put_json(envelope_key, envelope)
    corrupted = _execute(
        s3_fixture,
        surface.read_range(
            resource="object:tests.objects",
            reference=reference,
            byte_range={"start": 0, "end": 5},
        ),
    )
    with pytest.raises(DigestMismatch):
        transfer_payload(corrupted["payload"], s3_fixture.payloads, BytesIO())


def test_bounded_prefix_listing_uses_logical_cursor(s3_fixture: Any) -> None:
    for name in ("alpha/one", "beta/ignored", "alpha/two", "alpha/three"):
        _put(s3_fixture, name.encode(), object_id=name)
    surface = _provider().create_surface()
    cursor: str | None = None
    observed: set[str] = set()
    while True:
        page = _execute(
            s3_fixture,
            surface.list(
                resource="object:tests.objects",
                prefix="alpha/",
                limit=1,
                cursor=cursor,
            ),
        )
        items = page["items"]
        assert isinstance(items, list)
        assert len(items) <= 1
        if items:
            observed.add(items[0]["objectRef"]["objectId"])
        cursor = page["cursor"]
        if cursor is None:
            break
        assert isinstance(cursor, str)
    assert observed == {"alpha/one", "alpha/two", "alpha/three"}


def test_signed_reference_is_verified_inside_adapter(s3_fixture: Any) -> None:
    metadata = _metadata(_put(s3_fixture, b"signed", object_id="signed.bin"))
    signer = HmacSha256Key("key-1", b"x" * 32)
    signed = sign_object_reference(
        metadata["objectRef"],
        allowed_operations=("get", "stat"),
        expires_at=_timestamp(datetime.now(UTC) + timedelta(hours=1)),
        audience="reader",
        signer=signer,
        nonce="nonce-1",
    )
    adapter = S3ObjectAdapter(
        s3_fixture.adapter.transport,
        s3_fixture.adapter.config,
        payloads=s3_fixture.payloads,
        reference_signer=signer,
        signed_reference_audience="reader",
    )
    provider = _provider()
    result = adapter.execute(
        provider.normalize(
            provider.create_surface().stat(resource="object:tests.objects", reference=signed)
        ),
        s3_fixture.payloads,
    )
    assert result["metadata"]["digest"] == metadata["digest"]
    wrong_audience = S3ObjectAdapter(
        s3_fixture.adapter.transport,
        s3_fixture.adapter.config,
        payloads=s3_fixture.payloads,
        reference_signer=signer,
        signed_reference_audience="other",
    )
    with pytest.raises(ObjectAuthorizationFailed):
        wrong_audience.execute(
            provider.normalize(
                provider.create_surface().stat(resource="object:tests.objects", reference=signed)
            ),
            s3_fixture.payloads,
        )


def test_logical_retention_denies_delete_and_missing_reference_is_stable(s3_fixture: Any) -> None:
    metadata = _metadata(
        _put(
            s3_fixture,
            b"retained",
            object_id="retained.bin",
            retention={
                "retainUntil": _timestamp(datetime.now(UTC) + timedelta(hours=1)),
                "policy": None,
                "requireEnforcement": False,
            },
        )
    )
    surface = _provider().create_surface()
    with pytest.raises(RetentionDenied):
        _execute(
            s3_fixture,
            surface.delete(resource="object:tests.objects", reference=metadata["objectRef"]),
        )
    missing = {
        "resourceRef": metadata["objectRef"]["resourceRef"],
        "objectId": "missing",
        "digest": "sha256:" + "0" * 64,
    }
    with pytest.raises(ObjectNotFound):
        _execute(
            s3_fixture,
            surface.stat(resource="object:tests.objects", reference=missing),
        )
