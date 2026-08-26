# SPDX-License-Identifier: Apache-2.0
"""Private S3 transport and multipart safety-boundary tests."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from botocore.exceptions import ClientError
from meridian_storage.object_common import (
    DigestMismatch,
    IncompleteUpload,
    MultipartInvalid,
    ObjectInvalidRequest,
    ObjectNotFound,
)

from meridian_storage.adapters.s3 import S3Config, S3Credentials
from meridian_storage.adapters.s3.multipart import upload_multipart
from meridian_storage.adapters.s3.retention import RetentionRecord
from meridian_storage.adapters.s3.transport import S3Transport, create_s3_client


def _client_error(code: str, operation: str = "S3") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "private provider detail"}}, operation)


class _RecordingClient:
    def __init__(self) -> None:
        self.closed = False
        self.requests: list[tuple[str, dict[str, object]]] = []
        self.objects: dict[str, bytes] = {}

    def close(self) -> None:
        self.closed = True

    def head_bucket(self, **request: object) -> None:
        self.requests.append(("head_bucket", request))

    def get_bucket_versioning(self, **request: object) -> dict[str, object]:
        self.requests.append(("get_bucket_versioning", request))
        return {}

    def get_object_lock_configuration(self, **request: object) -> dict[str, object]:
        self.requests.append(("get_object_lock_configuration", request))
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def head_object(self, **request: object) -> dict[str, object]:
        self.requests.append(("head_object", request))
        return {
            "ContentLength": 3,
            "ContentType": "text/plain",
            "Metadata": {"one": 1},
            "VersionId": "v1",
            "ETag": '"etag"',
        }

    def get_object(self, **request: object) -> dict[str, object]:
        self.requests.append(("get_object", request))
        key = str(request["Key"])
        return {"Body": BytesIO(self.objects.get(key, b"payload"))}

    def put_object(self, **request: object) -> dict[str, object]:
        self.requests.append(("put_object", request))
        body = request["Body"]
        raw = body.read() if hasattr(body, "read") else bytes(body)  # type: ignore[arg-type,union-attr]
        self.objects[str(request["Key"])] = bytes(raw)
        return {"VersionId": "v2", "ETag": '"stored"'}

    def delete_object(self, **request: object) -> None:
        self.requests.append(("delete_object", request))

    def list_objects_v2(self, **request: object) -> dict[str, object]:
        self.requests.append(("list_objects_v2", request))
        return {
            "Contents": [{"Key": "prefix/a"}, {"Key": 7}, "invalid"],
            "IsTruncated": True,
        }


def test_create_client_keeps_credentials_inside_sdk_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class Session:
        def client(self, service: str, **kwargs: object) -> object:
            captured["service"] = service
            captured.update(kwargs)
            return object()

    monkeypatch.setattr(
        "meridian_storage.adapters.s3.transport.boto3.session.Session", lambda: Session()
    )
    config = S3Config(
        bucket="valid-bucket",
        endpoint_url="https://s3.example.test",
        addressing_style="virtual",
        max_attempts=9,
    )
    created = create_s3_client(
        config, S3Credentials("access", "secret", "token"), verify="/private/ca.pem"
    )
    assert created is not None
    assert captured["service"] == "s3"
    assert captured["endpoint_url"] == "https://s3.example.test"
    assert captured["aws_access_key_id"] == "access"
    assert captured["aws_secret_access_key"] == "secret"
    assert captured["aws_session_token"] == "token"
    assert captured["verify"] == "/private/ca.pem"


def test_transport_metadata_reads_writes_listing_and_delete_requests() -> None:
    client = _RecordingClient()
    config = S3Config(
        bucket="valid-bucket",
        prefix="private",
        verify_after_write=False,
        checksum_headers=True,
        server_side_encryption="AES256",
    )
    transport = S3Transport(client, config)
    transport.head_bucket()
    assert transport.versioning_status() == "Disabled"
    assert transport.object_lock_enabled()
    head = transport.head("key", version_id="v1")
    assert head.byte_length == 3
    assert head.metadata == {"one": "1"}
    body = transport.get_body("key", version_id="v1", byte_range=(1, 2))
    assert body.read() == b"payload"
    stored = transport.put_file(
        "bytes",
        BytesIO(b"abc"),
        length=3,
        digest="sha256:" + hashlib.sha256(b"abc").hexdigest(),
        content_type="text/plain",
        metadata={"logical": "true"},
        create_only=True,
    )
    assert stored.version_id == "v2"
    put_request = next(request for name, request in client.requests if name == "put_object")
    assert put_request["IfNoneMatch"] == "*"
    assert put_request["ServerSideEncryption"] == "AES256"
    assert (
        put_request["ChecksumSHA256"] == base64.b64encode(hashlib.sha256(b"abc").digest()).decode()
    )
    transport.put_json("document", {"hello": "world"}, create_only=True)
    assert transport.read_json("document") == {"hello": "world"}
    page = transport.list_keys("prefix/", max_keys=3, start_after="prefix/old")
    assert page.keys == ("prefix/a",)
    assert page.truncated
    transport.delete("key", version_id="v9", retention_sensitive=True)
    delete = next(request for name, request in client.requests if name == "delete_object")
    assert delete["VersionId"] == "v9"
    transport.close()
    assert client.closed


def test_transport_object_lock_absence_and_normalized_failures() -> None:
    class FailingClient:
        def get_object_lock_configuration(self, **request: object) -> object:
            raise _client_error("ObjectLockConfigurationNotFoundError")

        def get_object(self, **request: object) -> dict[str, object]:
            return {}

        def delete_object(self, **request: object) -> None:
            raise _client_error("NoSuchKey")

    transport = S3Transport(FailingClient(), S3Config(bucket="valid-bucket"))
    assert not transport.object_lock_enabled()
    with pytest.raises(IncompleteUpload, match="streaming response"):
        transport.get_body("missing")
    with pytest.raises(ObjectNotFound):
        transport.delete("missing")

    class UnknownLock:
        def get_object_lock_configuration(self, **request: object) -> object:
            raise _client_error("SlowDown")

    with pytest.raises(Exception, match="rate limited"):
        S3Transport(UnknownLock(), S3Config(bucket="valid-bucket")).object_lock_enabled()


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"not-json", DigestMismatch),
        (b"[]", DigestMismatch),
        (b"x" * (4 * 1024 * 1024 + 1), ObjectInvalidRequest),
    ],
)
def test_internal_json_is_bounded_and_must_be_an_object(
    payload: bytes, expected: type[Exception]
) -> None:
    class Client:
        def get_object(self, **request: object) -> dict[str, object]:
            return {"Body": BytesIO(payload)}

    with pytest.raises(expected):
        S3Transport(Client(), S3Config(bucket="valid-bucket")).read_json("metadata")


def test_verify_digest_rejects_length_digest_and_nonbinary_streams() -> None:
    config = S3Config(bucket="valid-bucket")

    class Client:
        value: object = b"abc"

        def get_object(self, **request: object) -> dict[str, object]:
            class Body:
                used = False

                def read(self, size: int = -1) -> object:
                    if self.used:
                        return b""
                    self.used = True
                    return Client.value

                def close(self) -> None:
                    pass

            return {"Body": Body()}

    client = Client()
    transport = S3Transport(client, config)
    correct = "sha256:" + hashlib.sha256(b"abc").hexdigest()
    transport.verify_digest("key", digest=correct, length=3)
    with pytest.raises(IncompleteUpload, match="length"):
        transport.verify_digest("key", digest=correct, length=2)
    with pytest.raises(DigestMismatch, match="digest"):
        transport.verify_digest("key", digest="sha256:" + "0" * 64, length=3)
    Client.value = "not-binary"
    with pytest.raises(IncompleteUpload, match="non-binary"):
        transport.verify_digest("key", digest=correct, length=3)


def test_transport_size_bound_and_retention_write_arguments() -> None:
    client = _RecordingClient()
    config = S3Config(
        bucket="valid-bucket",
        max_object_bytes=5 * 1024 * 1024,
        max_range_bytes=5 * 1024 * 1024,
        multipart_threshold_bytes=5 * 1024 * 1024,
        verify_after_write=False,
        server_side_encryption="aws:kms",
        kms_key_id="alias/meridian",
    )
    transport = S3Transport(client, config)
    with pytest.raises(ObjectInvalidRequest, match="size limit"):
        transport.put_file(
            "large",
            BytesIO(b"123456"),
            length=5 * 1024 * 1024 + 1,
            digest="sha256:" + "0" * 64,
            content_type="application/octet-stream",
            metadata={},
        )
    deadline = (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    retention = RetentionRecord(deadline, None, True, True, "COMPLIANCE")
    transport.put_json("locked", {"value": 1}, retention=retention)
    request = next(request for name, request in client.requests if name == "put_object")
    assert request["ObjectLockMode"] == "COMPLIANCE"
    assert request["SSEKMSKeyId"] == "alias/meridian"
    assert "ChecksumSHA256" in request


class _MultipartClient:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, object]]] = []
        self.upload_id: object = "upload-1"
        self.etag: object = '"part"'
        self.return_checksum = True
        self.bad_checksum = False
        self.aborted = False

    def create_multipart_upload(self, **request: object) -> dict[str, object]:
        self.requests.append(("create", request))
        return {"UploadId": self.upload_id}

    def upload_part(self, **request: object) -> dict[str, object]:
        self.requests.append(("part", request))
        result: dict[str, object] = {"ETag": self.etag}
        if self.return_checksum and "ChecksumSHA256" in request:
            checksum = request["ChecksumSHA256"]
            result["ChecksumSHA256"] = "wrong" if self.bad_checksum else checksum
        return result

    def complete_multipart_upload(self, **request: object) -> dict[str, object]:
        self.requests.append(("complete", request))
        return {"VersionId": "v3"}

    def abort_multipart_upload(self, **request: object) -> None:
        self.aborted = True
        self.requests.append(("abort", request))


def test_multipart_success_records_verified_part_evidence() -> None:
    client = _MultipartClient()
    evidence = upload_multipart(
        client,
        bucket="bucket",
        key="key",
        stream=BytesIO(b"abcdef"),
        length=6,
        part_size=3,
        content_type="application/octet-stream",
        metadata={"format": "object-v1"},
        create_arguments={"ServerSideEncryption": "AES256"},
        checksum_headers=True,
    )
    assert evidence.upload_id == "upload-1"
    assert evidence.version_id == "v3"
    assert evidence.part_count == 2
    assert evidence.part_digests == (
        "sha256:" + hashlib.sha256(b"abc").hexdigest(),
        "sha256:" + hashlib.sha256(b"def").hexdigest(),
    )
    assert [name for name, _ in client.requests] == ["create", "part", "part", "complete"]


def test_multipart_rejects_limits_and_aborts_every_incomplete_upload() -> None:
    with pytest.raises(MultipartInvalid, match="part-count"):
        upload_multipart(
            _MultipartClient(),
            bucket="bucket",
            key="key",
            stream=BytesIO(),
            length=10_001 * 5,
            part_size=5,
            content_type="application/octet-stream",
            metadata={},
            create_arguments={},
            checksum_headers=False,
        )
    missing_id = _MultipartClient()
    missing_id.upload_id = None
    with pytest.raises(IncompleteUpload, match="upload id"):
        upload_multipart(
            missing_id,
            bucket="bucket",
            key="key",
            stream=BytesIO(b"abc"),
            length=3,
            part_size=3,
            content_type="application/octet-stream",
            metadata={},
            create_arguments={},
            checksum_headers=False,
        )

    clients: list[_MultipartClient] = []
    cases = [
        (BytesIO(), 3, "ended"),
        (BytesIO(b"abcd"), 3, "declaration"),
    ]
    for stream, length, message in cases:
        client = _MultipartClient()
        clients.append(client)
        with pytest.raises(IncompleteUpload, match=message):
            upload_multipart(
                client,
                bucket="bucket",
                key="key",
                stream=stream,
                length=length,
                part_size=3,
                content_type="application/octet-stream",
                metadata={},
                create_arguments={},
                checksum_headers=False,
            )
    no_etag = _MultipartClient()
    no_etag.etag = None
    clients.append(no_etag)
    with pytest.raises(IncompleteUpload, match="completed multipart part"):
        upload_multipart(
            no_etag,
            bucket="bucket",
            key="key",
            stream=BytesIO(b"abc"),
            length=3,
            part_size=3,
            content_type="application/octet-stream",
            metadata={},
            create_arguments={},
            checksum_headers=False,
        )
    bad_checksum = _MultipartClient()
    bad_checksum.bad_checksum = True
    clients.append(bad_checksum)
    with pytest.raises(IncompleteUpload, match="mismatched"):
        upload_multipart(
            bad_checksum,
            bucket="bucket",
            key="key",
            stream=BytesIO(b"abc"),
            length=3,
            part_size=3,
            content_type="application/octet-stream",
            metadata={},
            create_arguments={},
            checksum_headers=True,
        )
    assert all(client.aborted for client in clients)
