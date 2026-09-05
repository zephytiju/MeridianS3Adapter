# SPDX-License-Identifier: Apache-2.0
"""Meridian Object operation execution over a private S3 transport."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from tempfile import SpooledTemporaryFile
from typing import IO, BinaryIO, cast

from meridian_storage.context import OperationContext
from meridian_storage.object_common import (
    ByteRange,
    ConditionalConflict,
    DigestMismatch,
    ImmutableObjectConflict,
    ObjectAuthorizationFailed,
    ObjectInvalidRequest,
    ObjectMetadata,
    ObjectNotFound,
    ObjectProfile,
    ObjectReference,
    PayloadReference,
    PayloadRegistry,
    PutState,
    PutStateMachine,
    ReferenceSigner,
    ResolvedByteRange,
    SignedObjectReference,
    default_payload_registry,
    effective_immutability,
    parse_logical_reference,
    parse_object_metadata,
    parse_object_profile,
    transfer_payload,
)
from meridian_storage.semantics import CatalogName, FrozenJson, ResourceReference

from meridian_storage import Operation, ResourceRef

from ._version import __version__
from .config import S3Config
from .descriptor import S3_ADAPTER_ID
from .layout import S3Layout
from .retention import RetentionRecord, parse_retention_request
from .transport import S3Transport

_ENVELOPE_VERSION = "meridian.s3-object-envelope.v1"
_LATEST_VERSION = "meridian.s3-object-latest.v1"
_MAX_INTERNAL_LIST_PAGES = 10


def _now() -> datetime:
    return datetime.now(UTC)


def _json_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ObjectInvalidRequest(f"{name} must be an object")
    return cast(Mapping[str, object], value)


class _IntegritySpool:
    def __init__(self, stream: IO[bytes], chunk_bytes: int) -> None:
        self._stream = stream
        self._chunk_bytes = chunk_bytes
        self._chunk_hasher = hashlib.sha256()
        self._chunk_length = 0
        self._digests: list[str] = []

    def write(self, data: bytes) -> int:
        raw = bytes(data)
        written = self._stream.write(raw)
        if written != len(raw):
            return written
        offset = 0
        while offset < len(raw):
            selected = min(self._chunk_bytes - self._chunk_length, len(raw) - offset)
            self._chunk_hasher.update(raw[offset : offset + selected])
            self._chunk_length += selected
            offset += selected
            if self._chunk_length == self._chunk_bytes:
                self._finish_chunk()
        return written

    def _finish_chunk(self) -> None:
        self._digests.append(f"sha256:{self._chunk_hasher.hexdigest()}")
        self._chunk_hasher = hashlib.sha256()
        self._chunk_length = 0

    def finish(self) -> tuple[str, ...]:
        if self._chunk_length:
            self._finish_chunk()
        return tuple(self._digests)


class _S3PayloadSource:
    def __init__(
        self,
        transport: S3Transport,
        key: str,
        version_id: str | None,
    ) -> None:
        self._transport = transport
        self._key = key
        self._version_id = version_id

    @property
    def replayable(self) -> bool:
        return True

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        body = self._transport.get_body(self._key, version_id=self._version_id)
        try:
            yield cast(BinaryIO, body)
        finally:
            body.close()


class _LimitedReader:
    def __init__(self, stream: IO[bytes], length: int) -> None:
        self._stream = stream
        self._remaining = length

    def read(self, size: int = -1) -> bytes:
        if self._remaining == 0:
            return b""
        selected = self._remaining if size < 0 else min(size, self._remaining)
        value = self._stream.read(selected)
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError("verified range stream returned non-binary data")
        raw = bytes(value)
        self._remaining -= len(raw)
        return raw


class _VerifiedRangeSource:
    def __init__(
        self,
        transport: S3Transport,
        config: S3Config,
        key: str,
        version_id: str | None,
        resolved: ResolvedByteRange,
        chunk_digests: tuple[str, ...],
    ) -> None:
        self._transport = transport
        self._config = config
        self._key = key
        self._version_id = version_id
        self._resolved = resolved
        self._chunk_digests = chunk_digests

    @property
    def replayable(self) -> bool:
        return True

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        start = self._resolved.start
        end = self._resolved.end
        total = self._resolved.total_length
        length = self._resolved.length
        chunk_bytes = self._config.integrity_chunk_bytes
        first_chunk = start // chunk_bytes
        last_chunk = end // chunk_bytes
        covering_start = first_chunk * chunk_bytes
        covering_end = min(total - 1, (last_chunk + 1) * chunk_bytes - 1)
        body = self._transport.get_body(
            self._key,
            version_id=self._version_id,
            byte_range=(covering_start, covering_end),
        )
        spool = SpooledTemporaryFile(  # noqa: SIM115 - closed in the generator's finally block
            max_size=self._config.spool_memory_bytes, mode="w+b"
        )
        observed = 0
        current_chunk = first_chunk
        hasher = hashlib.sha256()
        current_length = 0
        try:
            while True:
                raw_value = body.read(
                    min(1024 * 1024, covering_end - covering_start + 1 - observed)
                )
                if raw_value == b"":
                    break
                if not isinstance(raw_value, (bytes, bytearray, memoryview)):
                    raise TypeError("S3 range response returned non-binary data")
                raw = bytes(raw_value)
                spool.write(raw)
                observed += len(raw)
                offset = 0
                while offset < len(raw):
                    expected_chunk_length = min(chunk_bytes, total - current_chunk * chunk_bytes)
                    selected = min(expected_chunk_length - current_length, len(raw) - offset)
                    hasher.update(raw[offset : offset + selected])
                    current_length += selected
                    offset += selected
                    if current_length == expected_chunk_length:
                        digest = f"sha256:{hasher.hexdigest()}"
                        if current_chunk >= len(self._chunk_digests) or (
                            digest != self._chunk_digests[current_chunk]
                        ):
                            raise DigestMismatch("S3 range chunk failed integrity verification")
                        current_chunk += 1
                        hasher = hashlib.sha256()
                        current_length = 0
            expected_covering = covering_end - covering_start + 1
            if observed != expected_covering or current_chunk != last_chunk + 1:
                raise DigestMismatch("S3 range response was incomplete")
            spool.seek(start - covering_start)
            yield cast(BinaryIO, _LimitedReader(spool, length))
        finally:
            body.close()
            spool.close()


@dataclass(frozen=True, slots=True)
class _StoredEnvelope:
    metadata: ObjectMetadata
    blob_version_id: str | None
    retention: RetentionRecord | None
    integrity_chunk_bytes: int
    chunk_digests: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "formatVersion": _ENVELOPE_VERSION,
            "metadata": self.metadata.to_dict(),
            "blobVersionId": self.blob_version_id,
            "retention": None if self.retention is None else self.retention.to_dict(),
            "integrity": {
                "chunkBytes": self.integrity_chunk_bytes,
                "chunkDigests": list(self.chunk_digests),
            },
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> _StoredEnvelope:
        if (
            set(value)
            != {
                "formatVersion",
                "metadata",
                "blobVersionId",
                "retention",
                "integrity",
            }
            or value["formatVersion"] != _ENVELOPE_VERSION
        ):
            raise DigestMismatch("stored S3 Object envelope is invalid")
        metadata_value = _json_mapping(value["metadata"], "stored metadata")
        retention_value = value["retention"]
        if retention_value is not None and not isinstance(retention_value, Mapping):
            raise DigestMismatch("stored S3 retention record is invalid")
        integrity = _json_mapping(value["integrity"], "stored integrity")
        if set(integrity) != {"chunkBytes", "chunkDigests"}:
            raise DigestMismatch("stored S3 integrity record is invalid")
        chunk_bytes = integrity["chunkBytes"]
        raw_digests = integrity["chunkDigests"]
        if (
            isinstance(chunk_bytes, bool)
            or not isinstance(chunk_bytes, int)
            or not isinstance(raw_digests, list)
            or any(not isinstance(item, str) for item in raw_digests)
        ):
            raise DigestMismatch("stored S3 integrity record is invalid")
        return cls(
            metadata=parse_object_metadata(metadata_value),
            blob_version_id=cast(str | None, value["blobVersionId"]),
            retention=RetentionRecord.from_mapping(
                cast(Mapping[str, object] | None, retention_value)
            ),
            integrity_chunk_bytes=chunk_bytes,
            chunk_digests=tuple(cast(list[str], raw_digests)),
        )


class S3ObjectAdapter:
    """Execute normalized Object Operations without exposing any S3 value to consumers."""

    target_id = "s3"

    def __init__(
        self,
        transport: S3Transport,
        config: S3Config,
        *,
        payloads: PayloadRegistry | None = None,
        reference_signer: ReferenceSigner | None = None,
        signed_reference_audience: str | None = None,
    ) -> None:
        self.transport = transport
        self.config = config
        self.payloads = default_payload_registry() if payloads is None else payloads
        self.layout = S3Layout(config)
        self.reference_signer = reference_signer
        self.signed_reference_audience = signed_reference_audience

    def reset(self) -> None:
        """Conformance target reset hook; disposable bucket lifecycle remains external."""

    def execute(
        self,
        operation: Operation,
        payloads: PayloadRegistry | None = None,
        *,
        context: OperationContext | None = None,
    ) -> Mapping[str, object]:
        if not isinstance(operation, Operation) or operation.catalog != "object":
            raise ObjectInvalidRequest("S3 Adapter accepts only normalized Object Operations")
        if operation.operation_version != "1.0.0":
            raise ObjectInvalidRequest("S3 Adapter does not support this Object Operation version")
        method = operation.operation_contract.removeprefix("meridian.object.")
        if method not in {
            "publish_schema",
            "create_resource",
            "put",
            "get",
            "stat",
            "read_range",
            "list",
            "delete",
        }:
            raise ObjectInvalidRequest("S3 Adapter does not support this Object Operation")
        selected_payloads = self.payloads if payloads is None else payloads
        if method == "publish_schema":
            return self._publish_schema(operation)
        if method == "create_resource":
            return self._create_resource(operation)
        if method == "put":
            return self._put(operation, selected_payloads, context)
        if method == "get":
            return self._get(operation, selected_payloads)
        if method == "stat":
            return {"metadata": self._stat(operation).metadata.to_dict()}
        if method == "read_range":
            return self._read_range(operation, selected_payloads)
        if method == "list":
            return self._list(operation)
        return self._delete(operation)

    def _publish_schema(self, operation: Operation) -> Mapping[str, object]:
        value = operation.input
        document = {
            "formatVersion": "meridian.s3-object-schema.v1",
            "namespace": value["namespace"],
            "name": value["name"],
            "version": value["version"],
            "definition": value["definition"],
        }
        key = self.layout.schema_key(
            cast(str, value["namespace"]),
            cast(str, value["name"]),
            cast(str, value["version"]),
        )
        try:
            self.transport.put_json(key, document, create_only=True)
            created = True
        except ConditionalConflict:
            if self.transport.read_json(key) != document:
                raise ConditionalConflict(
                    "Object Schema version already has a different definition"
                ) from None
            created = False
        return {
            "schema": {
                "catalog": "object",
                "namespace": value["namespace"],
                "name": value["name"],
                "version": value["version"],
            },
            "created": created,
        }

    def _create_resource(self, operation: Operation) -> Mapping[str, object]:
        value = operation.input
        resource = ResourceRef("object", cast(str, value["namespace"]), cast(str, value["name"]))
        profile = parse_object_profile(cast(Mapping[str, object], value["profile"]))
        document = {
            "formatVersion": "meridian.s3-object-resource.v1",
            "resourceRef": resource.to_dict(),
            "profile": profile.to_dict(),
            "options": value["options"],
        }
        key = self.layout.resource_key(resource)
        try:
            self.transport.put_json(key, document, create_only=True)
            created = True
        except ConditionalConflict:
            if self.transport.read_json(key) != document:
                raise ConditionalConflict(
                    "Object Resource already has a different definition"
                ) from None
            created = False
        return {"resource": resource.to_dict(), "profile": profile.to_dict(), "created": created}

    def _put(
        self,
        operation: Operation,
        payloads: PayloadRegistry,
        context: OperationContext | None,
    ) -> Mapping[str, object]:
        value = operation.input
        resource = operation.resources[0]
        object_id = cast(str, value["objectId"])
        create_only = cast(bool, value["createOnly"])
        profile = self._resource_profile(resource)
        raw_immutability = value["immutability"]
        immutability = effective_immutability(
            profile,
            cast(Mapping[str, object] | None, raw_immutability),
        )
        retention_request = parse_retention_request(value["retention"])
        retention = RetentionRecord.from_request(retention_request, self.config)
        creation_context = cast(
            Mapping[str, FrozenJson],
            _json_mapping(value["creationContext"], "creationContext"),
        )
        raw_provenance = dict(_json_mapping(value["provenance"], "provenance"))
        if "meridian.adapter" in raw_provenance:
            raise ObjectInvalidRequest("provenance key 'meridian.adapter' is reserved")
        raw_provenance["meridian.adapter"] = {
            "adapterId": S3_ADAPTER_ID,
            "adapterVersion": __version__,
            "engineProfile": self.config.engine_profile,
        }
        existing = self._try_latest(resource, object_id)
        if existing is not None and create_only:
            raise ConditionalConflict("create-only Object id already exists")
        raw_payload = _json_mapping(value["payload"], "payload")
        reference = PayloadReference.from_mapping(raw_payload)
        state = PutStateMachine()
        state.transition(PutState.UPLOADING)
        spool = SpooledTemporaryFile(  # noqa: SIM115 - closed in the operation's finally block
            max_size=self.config.spool_memory_bytes, mode="w+b"
        )
        sink = _IntegritySpool(spool, self.config.integrity_chunk_bytes)
        physical_commit_possible = False
        try:
            cancelled: Callable[[], bool] | None = None
            if context is not None:

                def deadline_expired() -> bool:
                    return context.remaining_seconds() == 0

                cancelled = deadline_expired
            identity = transfer_payload(reference, payloads, sink, cancelled=cancelled)
            chunks = sink.finish()
            if identity.byte_length > self.config.max_object_bytes:
                raise ObjectInvalidRequest("Object exceeds the configured S3 size limit")
            state.transition(PutState.VERIFYING)
            latest_after_stream = self._try_latest(resource, object_id)
            if latest_after_stream is not None:
                if create_only:
                    raise ConditionalConflict("create-only Object id already exists")
                if latest_after_stream.metadata.digest == identity.digest:
                    self._require_idempotent_metadata(
                        latest_after_stream.metadata,
                        media_type=cast(str, value["mediaType"]),
                        user_metadata=cast(Mapping[str, str], value["userMetadata"]),
                        mutability=immutability.mutability,
                        creation_context=creation_context,
                        provenance=cast(Mapping[str, FrozenJson], raw_provenance),
                        existing_retention=latest_after_stream.retention,
                        requested_retention=retention,
                    )
                    state.transition(PutState.COMMITTED)
                    return {"metadata": latest_after_stream.metadata.to_dict()}
                if immutability.mutability == "immutable":
                    raise ImmutableObjectConflict()
            logical_ref = ObjectReference(
                ResourceReference(CatalogName.OBJECT, resource.namespace, resource.name),
                object_id,
                identity.digest,
            )
            blob_key = self.layout.blob_key(resource, object_id, identity.digest)
            stored = self.transport.put_file(
                blob_key,
                spool,
                length=identity.byte_length,
                digest=identity.digest,
                content_type=cast(str, value["mediaType"]),
                metadata={
                    "meridian-digest": identity.digest.removeprefix("sha256:"),
                    "meridian-format": "object-v1",
                },
                retention=retention,
                create_only=True,
            )
            physical_commit_possible = True
            metadata = ObjectMetadata(
                object_ref=logical_ref,
                digest=identity.digest,
                byte_length=identity.byte_length,
                media_type=cast(str, value["mediaType"]),
                created_at=_now(),
                creation_context=creation_context,
                user_metadata=cast(Mapping[str, str], value["userMetadata"]),
                mutability=immutability.mutability,
                provenance=cast(Mapping[str, FrozenJson], raw_provenance),
            )
            envelope = _StoredEnvelope(
                metadata,
                stored.version_id,
                retention,
                self.config.integrity_chunk_bytes,
                chunks,
            )
            reference_key = self.layout.reference_key(resource, object_id, identity.digest)
            self.transport.put_json(
                reference_key,
                envelope.to_dict(),
                create_only=True,
                retention=retention,
            )
            latest_value = {
                "formatVersion": _LATEST_VERSION,
                "digest": identity.digest,
            }
            latest_create_only = create_only or immutability.mutability == "immutable"
            try:
                self.transport.put_json(
                    self.layout.latest_key(resource, object_id),
                    latest_value,
                    create_only=latest_create_only,
                )
            except ConditionalConflict:
                winner = self._try_latest(resource, object_id)
                if winner is None or winner.metadata.digest != identity.digest:
                    self._record_orphan(resource, object_id, identity.digest, "latest-conflict")
                raise ConditionalConflict(
                    "logical Object publication lost a conditional race"
                ) from None
            state.transition(PutState.COMMITTED)
            return {"metadata": metadata.to_dict()}
        except BaseException:
            if state.state in {PutState.UPLOADING, PutState.VERIFYING}:
                state.fail(physical_commit_possible=physical_commit_possible)
            raise
        finally:
            spool.close()

    def _stat(self, operation: Operation) -> _StoredEnvelope:
        resource = operation.resources[0]
        reference = self._reference(operation, require_digest=False)
        envelope = self._read_envelope(resource, reference.object_id, reference.digest)
        blob_key = self.layout.blob_key(
            resource,
            envelope.metadata.object_ref.object_id,
            envelope.metadata.digest,
        )
        head = self.transport.head(blob_key, version_id=envelope.blob_version_id)
        if head.byte_length != envelope.metadata.byte_length or head.metadata.get(
            "meridian-digest"
        ) != envelope.metadata.digest.removeprefix("sha256:"):
            raise DigestMismatch("S3 Object metadata does not match its physical bytes")
        return envelope

    def _get(self, operation: Operation, payloads: PayloadRegistry) -> Mapping[str, object]:
        envelope = self._stat(operation)
        metadata = envelope.metadata
        resource = operation.resources[0]
        source = _S3PayloadSource(
            self.transport,
            self.layout.blob_key(resource, metadata.object_ref.object_id, metadata.digest),
            envelope.blob_version_id,
        )
        payload = payloads.register(
            source,
            expected_length=metadata.byte_length,
            expected_digest=metadata.digest,
        )
        return {"metadata": metadata.to_dict(), "payload": payload.to_dict()}

    def _read_range(
        self,
        operation: Operation,
        payloads: PayloadRegistry,
    ) -> Mapping[str, object]:
        envelope = self._stat(operation)
        raw_range = _json_mapping(operation.input["range"], "range")
        selected = ByteRange.from_mapping(raw_range)
        resolved = selected.resolve(envelope.metadata.byte_length)
        if resolved.length > self.config.max_range_bytes:
            raise ObjectInvalidRequest("requested byte range exceeds the configured S3 limit")
        if envelope.integrity_chunk_bytes != self.config.integrity_chunk_bytes:
            raise DigestMismatch("stored Object integrity chunk format is incompatible")
        resource = operation.resources[0]
        source = _VerifiedRangeSource(
            self.transport,
            self.config,
            self.layout.blob_key(
                resource,
                envelope.metadata.object_ref.object_id,
                envelope.metadata.digest,
            ),
            envelope.blob_version_id,
            resolved,
            envelope.chunk_digests,
        )
        payload = payloads.register(source, expected_length=resolved.length)
        return {
            "metadata": envelope.metadata.to_dict(),
            "payload": payload.to_dict(),
            "range": resolved.to_dict(),
        }

    def _list(self, operation: Operation) -> Mapping[str, object]:
        resource = operation.resources[0]
        prefix = cast(str, operation.input["prefix"])
        limit = cast(int, operation.input["limit"])
        start_after = self.layout.start_after(
            resource,
            cast(str | None, operation.input["cursor"]),
        )
        items: list[dict[str, object]] = []
        last_scanned: str | None = None
        more = False
        reference_prefix = self.layout.reference_prefix(resource)
        for _ in range(_MAX_INTERNAL_LIST_PAGES):
            page = self.transport.list_keys(
                reference_prefix,
                max_keys=1000,
                start_after=start_after,
            )
            if not page.keys:
                more = False
                break
            for key in page.keys:
                if len(items) == limit:
                    more = True
                    break
                envelope = _StoredEnvelope.from_mapping(self.transport.read_json(key))
                last_scanned = key
                if envelope.metadata.object_ref.object_id.startswith(prefix):
                    items.append(cast(dict[str, object], envelope.metadata.to_dict()))
            if more:
                break
            if not page.truncated:
                more = False
                break
            start_after = page.keys[-1]
            more = True
        cursor = (
            self.layout.cursor_for_key(resource, last_scanned)
            if more and last_scanned is not None
            else None
        )
        return {"items": items, "cursor": cursor}

    def _delete(self, operation: Operation) -> Mapping[str, object]:
        resource = operation.resources[0]
        reference = self._reference(operation, require_digest=True)
        digest = reference.digest
        if digest is None:
            raise ObjectInvalidRequest("exact Object delete requires a digest")
        envelope = self._read_envelope(resource, reference.object_id, digest)
        if envelope.retention is not None:
            envelope.retention.require_delete_allowed()
        latest = self._try_latest(resource, reference.object_id)
        previous = self._newest_version(
            resource,
            reference.object_id,
            exclude_digest=digest,
        )
        blob_key = self.layout.blob_key(resource, reference.object_id, digest)
        exact_key = self.layout.reference_key(resource, reference.object_id, digest)
        exact_head = self.transport.head(exact_key)
        self.transport.delete(
            blob_key,
            version_id=envelope.blob_version_id,
            retention_sensitive=envelope.retention is not None,
        )
        self.transport.delete(
            exact_key,
            version_id=exact_head.version_id,
            retention_sensitive=envelope.retention is not None,
        )
        if latest is not None and latest.metadata.digest == digest:
            latest_key = self.layout.latest_key(resource, reference.object_id)
            if previous is not None:
                self.transport.put_json(
                    latest_key,
                    {"formatVersion": _LATEST_VERSION, "digest": previous.metadata.digest},
                )
            else:
                latest_head = self.transport.head(latest_key)
                self.transport.delete(latest_key, version_id=latest_head.version_id)
        self.transport.put_json(
            self.layout.deletion_evidence_key(resource, reference.object_id, digest),
            {
                "formatVersion": "meridian.s3-object-deletion.v1",
                "objectRef": reference.to_dict(),
                "deletedAt": _now().isoformat(),
                "reason": operation.input["reason"],
            },
            create_only=True,
        )
        return {"deleted": True}

    def _reference(self, operation: Operation, *, require_digest: bool) -> ObjectReference:
        raw = _json_mapping(operation.input["reference"], "reference")
        parsed = parse_logical_reference(raw)
        method = operation.operation_contract.removeprefix("meridian.object.")
        if isinstance(parsed, SignedObjectReference):
            if self.reference_signer is None or self.signed_reference_audience is None:
                raise ObjectAuthorizationFailed("signed Object references are not configured")
            reference = parsed.verify(
                self.reference_signer,
                operation=method,
                audience=self.signed_reference_audience,
            )
        else:
            reference = parsed
        if require_digest and reference.digest is None:
            raise ObjectInvalidRequest("exact Object operation requires a digest")
        resource = operation.resources[0]
        selected = reference.resource_ref
        if (selected.namespace, selected.name) != (resource.namespace, resource.name):
            raise ObjectInvalidRequest("Object reference does not belong to the target Resource")
        return reference

    def _resource_profile(self, resource: ResourceRef) -> ObjectProfile:
        try:
            value = self.transport.read_json(self.layout.resource_key(resource))
        except ObjectNotFound:
            return ObjectProfile()
        raw_profile = value.get("profile")
        if not isinstance(raw_profile, Mapping):
            raise DigestMismatch("stored Object Resource profile is corrupt")
        return parse_object_profile(cast(Mapping[str, object], raw_profile))

    def _try_latest(self, resource: ResourceRef, object_id: str) -> _StoredEnvelope | None:
        try:
            return self._read_envelope(resource, object_id, None)
        except ObjectNotFound:
            return None

    def _read_envelope(
        self,
        resource: ResourceRef,
        object_id: str,
        digest: str | None,
    ) -> _StoredEnvelope:
        selected_digest = digest
        if selected_digest is None:
            latest = self.transport.read_json(self.layout.latest_key(resource, object_id))
            if (
                set(latest) != {"formatVersion", "digest"}
                or latest.get("formatVersion") != _LATEST_VERSION
            ):
                raise DigestMismatch("stored S3 latest Object pointer is invalid")
            selected_digest = cast(str, latest["digest"])
        value = self.transport.read_json(
            self.layout.reference_key(resource, object_id, selected_digest)
        )
        envelope = _StoredEnvelope.from_mapping(value)
        metadata_ref = envelope.metadata.object_ref
        if metadata_ref.object_id != object_id or envelope.metadata.digest != selected_digest:
            raise DigestMismatch("stored S3 Object envelope identity does not match its key")
        return envelope

    def _record_orphan(
        self,
        resource: ResourceRef,
        object_id: str,
        digest: str,
        reason: str,
    ) -> None:
        with suppress(ConditionalConflict):
            self.transport.put_json(
                self.layout.orphan_key(resource, object_id, digest),
                {
                    "formatVersion": "meridian.s3-orphan-candidate.v1",
                    "objectRef": {
                        "resourceRef": resource.to_dict(),
                        "objectId": object_id,
                        "digest": digest,
                    },
                    "observedAt": _now().isoformat(),
                    "reason": reason,
                },
                create_only=True,
            )

    def _newest_version(
        self,
        resource: ResourceRef,
        object_id: str,
        *,
        exclude_digest: str | None = None,
    ) -> _StoredEnvelope | None:
        prefix = f"{self.layout.reference_prefix(resource)}{self.layout.object_token(object_id)}/"
        start_after: str | None = None
        selected: _StoredEnvelope | None = None
        for _ in range(_MAX_INTERNAL_LIST_PAGES):
            page = self.transport.list_keys(prefix, max_keys=1000, start_after=start_after)
            for key in page.keys:
                envelope = _StoredEnvelope.from_mapping(self.transport.read_json(key))
                if envelope.metadata.digest == exclude_digest:
                    continue
                if selected is None or str(envelope.metadata.created_at) > str(
                    selected.metadata.created_at
                ):
                    selected = envelope
            if not page.truncated or not page.keys:
                break
            start_after = page.keys[-1]
        return selected

    @staticmethod
    def _require_idempotent_metadata(
        metadata: ObjectMetadata,
        *,
        media_type: str,
        user_metadata: Mapping[str, str],
        mutability: str,
        creation_context: Mapping[str, FrozenJson],
        provenance: Mapping[str, FrozenJson],
        existing_retention: RetentionRecord | None,
        requested_retention: RetentionRecord | None,
    ) -> None:
        if (
            metadata.media_type != media_type
            or dict(metadata.user_metadata) != dict(user_metadata)
            or metadata.mutability != mutability
            or dict(metadata.creation_context) != dict(creation_context)
            or dict(metadata.provenance) != dict(provenance)
            or existing_retention != requested_retention
        ):
            raise ConditionalConflict("the existing Object digest has different immutable metadata")


__all__ = ["S3ObjectAdapter"]
