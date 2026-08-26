# SPDX-License-Identifier: Apache-2.0
"""Low-level S3 multipart transfer with bounded parts and deterministic verification evidence."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import IO, Any

from meridian_storage.object_common import IncompleteUpload, MultipartInvalid

from .config import S3_MAX_MULTIPART_PARTS


@dataclass(frozen=True, slots=True)
class MultipartUploadEvidence:
    upload_id: str
    version_id: str | None
    part_count: int
    part_digests: tuple[str, ...]


def upload_multipart(
    client: Any,
    *,
    bucket: str,
    key: str,
    stream: IO[bytes],
    length: int,
    part_size: int,
    content_type: str,
    metadata: Mapping[str, str],
    create_arguments: Mapping[str, object],
    checksum_headers: bool,
) -> MultipartUploadEvidence:
    """Upload one already-verified seekable stream and abort every incomplete session."""

    expected_parts = max(1, (length + part_size - 1) // part_size)
    if expected_parts > S3_MAX_MULTIPART_PARTS:
        raise MultipartInvalid("multipart upload exceeds the S3 part-count limit")
    create: dict[str, object] = {
        "Bucket": bucket,
        "Key": key,
        "ContentType": content_type,
        "Metadata": dict(metadata),
        **create_arguments,
    }
    if checksum_headers:
        create["ChecksumAlgorithm"] = "SHA256"
    response = client.create_multipart_upload(**create)
    upload_id = response.get("UploadId")
    if not isinstance(upload_id, str) or not upload_id:
        raise IncompleteUpload("S3 did not return a multipart upload id")
    completed: list[dict[str, object]] = []
    part_digests: list[str] = []
    consumed = 0
    try:
        for number in range(1, expected_parts + 1):
            data = stream.read(min(part_size, length - consumed))
            if not isinstance(data, (bytes, bytearray, memoryview)) or not data:
                raise IncompleteUpload("multipart source ended before its declared length")
            raw = bytes(data)
            consumed += len(raw)
            digest_bytes = hashlib.sha256(raw).digest()
            digest = f"sha256:{digest_bytes.hex()}"
            request: dict[str, object] = {
                "Bucket": bucket,
                "Key": key,
                "UploadId": upload_id,
                "PartNumber": number,
                "Body": raw,
                "ContentLength": len(raw),
            }
            checksum = base64.b64encode(digest_bytes).decode("ascii")
            if checksum_headers:
                request["ChecksumSHA256"] = checksum
            uploaded = client.upload_part(**request)
            etag = uploaded.get("ETag")
            if not isinstance(etag, str) or not etag:
                raise IncompleteUpload("S3 did not verify a completed multipart part")
            returned_checksum = uploaded.get("ChecksumSHA256")
            if returned_checksum is not None and returned_checksum != checksum:
                raise IncompleteUpload("S3 returned a mismatched multipart part checksum")
            completed_part: dict[str, object] = {"ETag": etag, "PartNumber": number}
            if returned_checksum is not None:
                completed_part["ChecksumSHA256"] = returned_checksum
            completed.append(completed_part)
            part_digests.append(digest)
        if consumed != length or stream.read(1) not in {b"", None}:
            raise IncompleteUpload("multipart source length did not match its declaration")
        complete_request: dict[str, object] = {
            "Bucket": bucket,
            "Key": key,
            "UploadId": upload_id,
            "MultipartUpload": {"Parts": completed},
        }
        finished = client.complete_multipart_upload(**complete_request)
        return MultipartUploadEvidence(
            upload_id=upload_id,
            version_id=(
                finished.get("VersionId") if isinstance(finished.get("VersionId"), str) else None
            ),
            part_count=len(completed),
            part_digests=tuple(part_digests),
        )
    except BaseException:
        with suppress(BaseException):
            client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise


__all__ = ["MultipartUploadEvidence", "upload_multipart"]
