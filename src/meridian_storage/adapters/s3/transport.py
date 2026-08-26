# SPDX-License-Identifier: Apache-2.0
"""S3 SDK transport isolated from Meridian consumer contracts."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import IO, Any, cast

import boto3
from botocore.config import Config as BotocoreConfig
from meridian_storage.object_common import DigestMismatch, IncompleteUpload, ObjectInvalidRequest
from meridian_storage.semantics import JsonValue, canonical_json_bytes

from .config import S3Config, S3Credentials
from .errors import raise_normalized_s3_error
from .multipart import MultipartUploadEvidence, upload_multipart
from .retention import RetentionRecord

_MAX_INTERNAL_JSON_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class StoredObject:
    version_id: str | None
    etag: str | None
    multipart: MultipartUploadEvidence | None = None


@dataclass(frozen=True, slots=True)
class HeadObject:
    byte_length: int
    content_type: str
    metadata: Mapping[str, str]
    version_id: str | None
    etag: str | None


@dataclass(frozen=True, slots=True)
class KeyPage:
    keys: tuple[str, ...]
    truncated: bool


def create_s3_client(
    config: S3Config,
    credentials: S3Credentials,
    *,
    verify: bool | str = True,
) -> Any:
    sdk_config = BotocoreConfig(
        region_name=config.region,
        retries={"max_attempts": config.max_attempts, "mode": "standard"},
        s3={"addressing_style": config.addressing_style},
        user_agent_extra="meridian-storage-s3/1.0.0",
    )
    return boto3.session.Session().client(
        "s3",
        endpoint_url=config.endpoint_url,
        region_name=config.region,
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key,
        aws_session_token=credentials.session_token,
        verify=verify,
        config=sdk_config,
    )


class S3Transport:
    """Safe provider wrapper; all SDK failures are normalized before leaving this class."""

    def __init__(self, client: Any, config: S3Config) -> None:
        self.client = client
        self.config = config

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

    def head_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.config.bucket)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="health.head-bucket")

    def versioning_status(self) -> str:
        try:
            value = self.client.get_bucket_versioning(Bucket=self.config.bucket)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="health.bucket-versioning")
        status = value.get("Status")
        return status if isinstance(status, str) else "Disabled"

    def object_lock_enabled(self) -> bool:
        try:
            value = self.client.get_object_lock_configuration(Bucket=self.config.bucket)
        except BaseException as exc:
            normalized = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if normalized in {
                "InvalidBucketState",
                "ObjectLockConfigurationNotFoundError",
                "NotImplemented",
            }:
                return False
            raise_normalized_s3_error(exc, operation="health.object-lock")
        configuration = value.get("ObjectLockConfiguration", {})
        return (
            isinstance(configuration, Mapping)
            and configuration.get("ObjectLockEnabled") == "Enabled"
        )

    def head(self, key: str, *, version_id: str | None = None) -> HeadObject:
        request: dict[str, object] = {"Bucket": self.config.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        try:
            value = self.client.head_object(**request)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="stat")
        metadata = value.get("Metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}
        return HeadObject(
            byte_length=int(value.get("ContentLength", -1)),
            content_type=str(value.get("ContentType", "application/octet-stream")),
            metadata={str(key): str(item) for key, item in metadata.items()},
            version_id=(
                value.get("VersionId") if isinstance(value.get("VersionId"), str) else None
            ),
            etag=value.get("ETag") if isinstance(value.get("ETag"), str) else None,
        )

    def get_body(
        self,
        key: str,
        *,
        version_id: str | None = None,
        byte_range: tuple[int, int] | None = None,
    ) -> IO[bytes]:
        request: dict[str, object] = {"Bucket": self.config.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        if byte_range is not None:
            request["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
        try:
            value = self.client.get_object(**request)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="read_range" if byte_range else "get")
        body = value.get("Body")
        if body is None or not hasattr(body, "read"):
            raise IncompleteUpload("S3 did not return a streaming response body")
        return cast(IO[bytes], body)

    def put_file(
        self,
        key: str,
        stream: IO[bytes],
        *,
        length: int,
        digest: str,
        content_type: str,
        metadata: Mapping[str, str],
        retention: RetentionRecord | None = None,
        create_only: bool = False,
    ) -> StoredObject:
        if length > self.config.max_object_bytes:
            raise ObjectInvalidRequest("Object exceeds the configured S3 size limit")
        arguments = self._write_arguments(retention)
        use_checksum = self.config.checksum_headers or bool(
            retention is not None and retention.provider_enforced
        )
        stream.seek(0)
        try:
            if length >= self.config.multipart_threshold_bytes:
                evidence = upload_multipart(
                    self.client,
                    bucket=self.config.bucket,
                    key=key,
                    stream=stream,
                    length=length,
                    part_size=self.config.multipart_part_bytes,
                    content_type=content_type,
                    metadata=metadata,
                    create_arguments=arguments,
                    checksum_headers=use_checksum,
                )
                stored = StoredObject(evidence.version_id, None, evidence)
            else:
                request: dict[str, object] = {
                    "Bucket": self.config.bucket,
                    "Key": key,
                    "Body": stream,
                    "ContentLength": length,
                    "ContentType": content_type,
                    "Metadata": dict(metadata),
                    **arguments,
                }
                if create_only:
                    request["IfNoneMatch"] = "*"
                if use_checksum:
                    raw_digest = bytes.fromhex(digest.removeprefix("sha256:"))
                    request["ChecksumSHA256"] = base64.b64encode(raw_digest).decode("ascii")
                value = self.client.put_object(**request)
                stored = StoredObject(
                    value.get("VersionId") if isinstance(value.get("VersionId"), str) else None,
                    value.get("ETag") if isinstance(value.get("ETag"), str) else None,
                )
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="put")
        if self.config.verify_after_write:
            self.verify_digest(key, digest=digest, length=length, version_id=stored.version_id)
        return stored

    def put_json(
        self,
        key: str,
        value: Mapping[str, object],
        *,
        create_only: bool = False,
        retention: RetentionRecord | None = None,
    ) -> StoredObject:
        body = canonical_json_bytes(cast(JsonValue, value))
        request: dict[str, object] = {
            "Bucket": self.config.bucket,
            "Key": key,
            "Body": body,
            "ContentLength": len(body),
            "ContentType": "application/json",
            "Metadata": {"meridian-format": "object-v1"},
            **self._write_arguments(retention),
        }
        if create_only:
            request["IfNoneMatch"] = "*"
        if retention is not None and retention.provider_enforced:
            request["ChecksumSHA256"] = base64.b64encode(hashlib.sha256(body).digest()).decode(
                "ascii"
            )
        try:
            response = self.client.put_object(**request)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="metadata.put")
        return StoredObject(
            response.get("VersionId") if isinstance(response.get("VersionId"), str) else None,
            response.get("ETag") if isinstance(response.get("ETag"), str) else None,
        )

    def read_json(
        self,
        key: str,
        *,
        version_id: str | None = None,
    ) -> Mapping[str, object]:
        body = self.get_body(key, version_id=version_id)
        try:
            raw = body.read(_MAX_INTERNAL_JSON_BYTES + 1)
        finally:
            body.close()
        if (
            not isinstance(raw, (bytes, bytearray, memoryview))
            or len(raw) > _MAX_INTERNAL_JSON_BYTES
        ):
            raise ObjectInvalidRequest("stored Object metadata exceeds its safety bound")
        try:
            value = json.loads(bytes(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DigestMismatch("stored Object metadata is corrupt") from exc
        if not isinstance(value, Mapping):
            raise DigestMismatch("stored Object metadata is not an object")
        return cast(Mapping[str, object], value)

    def delete(
        self,
        key: str,
        *,
        version_id: str | None = None,
        retention_sensitive: bool = False,
    ) -> None:
        request: dict[str, object] = {"Bucket": self.config.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        try:
            self.client.delete_object(**request)
        except BaseException as exc:
            raise_normalized_s3_error(
                exc,
                operation="delete",
                retention_sensitive=retention_sensitive,
            )

    def list_keys(
        self,
        prefix: str,
        *,
        max_keys: int,
        start_after: str | None = None,
    ) -> KeyPage:
        request: dict[str, object] = {
            "Bucket": self.config.bucket,
            "Prefix": prefix,
            "MaxKeys": max_keys,
        }
        if start_after is not None:
            request["StartAfter"] = start_after
        try:
            value = self.client.list_objects_v2(**request)
        except BaseException as exc:
            raise_normalized_s3_error(exc, operation="list")
        contents = value.get("Contents", [])
        keys = tuple(
            item["Key"]
            for item in contents
            if isinstance(item, Mapping) and isinstance(item.get("Key"), str)
        )
        return KeyPage(keys, bool(value.get("IsTruncated", False)))

    def verify_digest(
        self,
        key: str,
        *,
        digest: str,
        length: int,
        version_id: str | None = None,
    ) -> None:
        body = self.get_body(key, version_id=version_id)
        hasher = hashlib.sha256()
        observed_length = 0
        try:
            while True:
                chunk = body.read(1024 * 1024)
                if chunk == b"":
                    break
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise IncompleteUpload("S3 response body returned non-binary data")
                raw = bytes(chunk)
                hasher.update(raw)
                observed_length += len(raw)
        finally:
            body.close()
        observed_digest = f"sha256:{hasher.hexdigest()}"
        if observed_length != length:
            raise IncompleteUpload("S3 stored length did not match the verified upload")
        if observed_digest != digest:
            raise DigestMismatch("S3 stored digest did not match the verified upload")

    def _write_arguments(self, retention: RetentionRecord | None) -> dict[str, object]:
        result: dict[str, object] = {}
        if self.config.server_side_encryption is not None:
            result["ServerSideEncryption"] = self.config.server_side_encryption
        if self.config.kms_key_id is not None:
            result["SSEKMSKeyId"] = self.config.kms_key_id
        if retention is not None:
            result.update(retention.object_lock_arguments())
        return result


__all__ = [
    "HeadObject",
    "KeyPage",
    "S3Transport",
    "StoredObject",
    "create_s3_client",
]
