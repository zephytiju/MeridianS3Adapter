# SPDX-License-Identifier: Apache-2.0
"""Closed, validated S3 configuration kept behind the Meridian Binding boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from meridian_storage.spi import AdapterCreateContext, SecretValue

_BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9]$")
_ALLOWED_SETTINGS = frozenset(
    {
        "addressingStyle",
        "allowInsecureHttp",
        "checksumHeaders",
        "integrityChunkBytes",
        "kmsKeyId",
        "maxAttempts",
        "maxObjectBytes",
        "maxRangeBytes",
        "multipartPartBytes",
        "multipartThresholdBytes",
        "objectLockMode",
        "region",
        "requireVersioning",
        "serverSideEncryption",
        "spoolMemoryBytes",
        "verifyAfterWrite",
    }
)

MIB = 1024 * 1024
GIB = 1024 * MIB
TIB = 1024 * GIB
S3_MIN_MULTIPART_PART_BYTES = 5 * MIB
S3_MAX_MULTIPART_PART_BYTES = 5 * GIB
S3_MAX_MULTIPART_PARTS = 10_000


def _bounded_string(value: object, name: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be a bounded non-empty string")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be boolean")
    return value


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class S3Credentials:
    """SDK credential material; representations never disclose secret values."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "access_key_id", _bounded_string(self.access_key_id, "access key"))
        object.__setattr__(
            self,
            "secret_access_key",
            _bounded_string(self.secret_access_key, "secret access key", 8192),
        )
        if self.session_token is not None:
            object.__setattr__(
                self,
                "session_token",
                _bounded_string(self.session_token, "session token", 16_384),
            )

    def __repr__(self) -> str:
        return "S3Credentials(<redacted>)"


@dataclass(frozen=True, slots=True)
class S3Config:
    """Validated deployment configuration for one IaC-owned bucket binding."""

    bucket: str
    prefix: str = ""
    endpoint_url: str | None = None
    region: str = "us-east-1"
    addressing_style: str = "path"
    allow_insecure_http: bool = False
    multipart_threshold_bytes: int = 16 * MIB
    multipart_part_bytes: int = 8 * MIB
    spool_memory_bytes: int = 8 * MIB
    integrity_chunk_bytes: int = MIB
    max_range_bytes: int = 64 * MIB
    max_object_bytes: int = 5 * TIB
    verify_after_write: bool = True
    checksum_headers: bool = False
    object_lock_mode: str | None = None
    server_side_encryption: str | None = None
    kms_key_id: str | None = None
    require_versioning: bool = False
    max_attempts: int = 4
    engine_profile: str = "s3-compatible"
    engine_version: str = "2006-03-01"

    def __post_init__(self) -> None:
        bucket = _bounded_string(self.bucket, "bucket", 255)
        if _BUCKET_RE.fullmatch(bucket) is None:
            raise ValueError("bucket must be a bounded S3-compatible bucket name")
        prefix = self.prefix.strip("/")
        if len(prefix.encode("utf-8")) > 768 or any(
            ord(character) < 32 or ord(character) == 127 for character in prefix
        ):
            raise ValueError("prefix must be a bounded control-free string")
        if any(segment in {".", ".."} for segment in prefix.split("/") if segment):
            raise ValueError("prefix cannot contain dot path segments")
        endpoint = self.endpoint_url
        if endpoint is not None:
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("endpoint_url must be an origin URL without credentials")
            if parsed.scheme == "http" and not self.allow_insecure_http:
                raise ValueError("HTTP endpoints require allow_insecure_http=True")
        if self.addressing_style not in {"auto", "path", "virtual"}:
            raise ValueError("addressing_style must be auto, path, or virtual")
        for name in ("region", "engine_profile", "engine_version"):
            object.__setattr__(self, name, _bounded_string(getattr(self, name), name, 256))
        _integer(
            self.multipart_part_bytes,
            "multipart_part_bytes",
            S3_MIN_MULTIPART_PART_BYTES,
            S3_MAX_MULTIPART_PART_BYTES,
        )
        _integer(
            self.multipart_threshold_bytes,
            "multipart_threshold_bytes",
            S3_MIN_MULTIPART_PART_BYTES,
            self.max_object_bytes,
        )
        _integer(self.spool_memory_bytes, "spool_memory_bytes", 64 * 1024, 256 * MIB)
        _integer(self.integrity_chunk_bytes, "integrity_chunk_bytes", 64 * 1024, 16 * MIB)
        _integer(self.max_range_bytes, "max_range_bytes", 1, self.max_object_bytes)
        _integer(self.max_object_bytes, "max_object_bytes", 1, 5 * TIB)
        _integer(self.max_attempts, "max_attempts", 1, 20)
        for name in (
            "allow_insecure_http",
            "verify_after_write",
            "checksum_headers",
            "require_versioning",
        ):
            _boolean(getattr(self, name), name)
        mode = self.object_lock_mode
        if mode is not None:
            normalized_mode = _bounded_string(mode, "object_lock_mode", 16).upper()
            if normalized_mode not in {"GOVERNANCE", "COMPLIANCE"}:
                raise ValueError("object_lock_mode must be GOVERNANCE or COMPLIANCE")
            object.__setattr__(self, "object_lock_mode", normalized_mode)
        encryption = self.server_side_encryption
        if encryption is not None and encryption not in {"AES256", "aws:kms"}:
            raise ValueError("server_side_encryption must be AES256 or aws:kms")
        if self.kms_key_id is not None:
            object.__setattr__(self, "kms_key_id", _bounded_string(self.kms_key_id, "kms_key_id"))
            if encryption != "aws:kms":
                raise ValueError("kms_key_id requires aws:kms server-side encryption")
        if encryption == "aws:kms" and self.kms_key_id is None:
            raise ValueError("aws:kms server-side encryption requires kms_key_id")
        object.__setattr__(self, "bucket", bucket)
        object.__setattr__(self, "prefix", prefix)

    @property
    def retention_enforcement(self) -> bool:
        return self.object_lock_mode is not None

    @property
    def namespace_root(self) -> str:
        return f"{self.prefix}/" if self.prefix else ""

    @classmethod
    def from_create_context(cls, context: AdapterCreateContext) -> S3Config:
        binding = context.binding
        if binding.adapter_id != "s3":
            raise ValueError("S3 Adapter factory requires an s3 Binding")
        if binding.endpoint is None:
            raise ValueError("S3 Binding serviceRef must be resolved to an endpoint by IaC")
        namespace = binding.physical_namespace.strip("/")
        bucket, separator, prefix = namespace.partition("/")
        if not bucket:
            raise ValueError("S3 physicalNamespace must contain a bucket")
        settings = cast(Mapping[str, object], binding.settings)
        unknown = set(settings) - _ALLOWED_SETTINGS
        if unknown:
            raise ValueError(f"S3 Binding contains unknown settings: {sorted(unknown)!r}")

        def setting(name: str, default: object) -> object:
            return settings.get(name, default)

        return cls(
            bucket=bucket,
            prefix=prefix if separator else "",
            endpoint_url=binding.endpoint,
            region=_bounded_string(setting("region", "us-east-1"), "region", 256),
            addressing_style=_bounded_string(
                setting("addressingStyle", "path"), "addressingStyle", 16
            ),
            allow_insecure_http=_boolean(setting("allowInsecureHttp", False), "allowInsecureHttp"),
            multipart_threshold_bytes=_integer(
                setting("multipartThresholdBytes", 16 * MIB),
                "multipartThresholdBytes",
                S3_MIN_MULTIPART_PART_BYTES,
                5 * TIB,
            ),
            multipart_part_bytes=_integer(
                setting("multipartPartBytes", 8 * MIB),
                "multipartPartBytes",
                S3_MIN_MULTIPART_PART_BYTES,
                S3_MAX_MULTIPART_PART_BYTES,
            ),
            spool_memory_bytes=_integer(
                setting("spoolMemoryBytes", 8 * MIB),
                "spoolMemoryBytes",
                64 * 1024,
                256 * MIB,
            ),
            integrity_chunk_bytes=_integer(
                setting("integrityChunkBytes", MIB),
                "integrityChunkBytes",
                64 * 1024,
                16 * MIB,
            ),
            max_range_bytes=_integer(
                setting("maxRangeBytes", 64 * MIB), "maxRangeBytes", 1, 5 * TIB
            ),
            max_object_bytes=_integer(
                setting("maxObjectBytes", 5 * TIB), "maxObjectBytes", 1, 5 * TIB
            ),
            verify_after_write=_boolean(setting("verifyAfterWrite", True), "verifyAfterWrite"),
            checksum_headers=_boolean(setting("checksumHeaders", False), "checksumHeaders"),
            object_lock_mode=cast(str | None, setting("objectLockMode", None)),
            server_side_encryption=cast(str | None, setting("serverSideEncryption", None)),
            kms_key_id=cast(str | None, setting("kmsKeyId", None)),
            require_versioning=_boolean(setting("requireVersioning", False), "requireVersioning"),
            max_attempts=_integer(setting("maxAttempts", 4), "maxAttempts", 1, 20),
            engine_profile=binding.engine_profile,
            engine_version=binding.engine_version,
        )


def credentials_from_secrets(identity: SecretValue, credential: SecretValue) -> S3Credentials:
    """Decode opaque Binding secret values without retaining or logging their byte forms."""

    try:
        access_key = identity.reveal().decode("utf-8")
        raw_credential = credential.reveal().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("S3 credential secret values must be UTF-8") from exc
    if raw_credential.lstrip().startswith("{"):
        try:
            value = json.loads(raw_credential)
        except json.JSONDecodeError as exc:
            raise ValueError("S3 credential JSON is invalid") from exc
        if not isinstance(value, dict) or set(value) - {"secretAccessKey", "sessionToken"}:
            raise ValueError("S3 credential JSON contains unknown fields")
        secret = value.get("secretAccessKey")
        token = value.get("sessionToken")
        if not isinstance(secret, str) or (token is not None and not isinstance(token, str)):
            raise ValueError("S3 credential JSON fields must be strings")
        return S3Credentials(access_key, secret, token)
    return S3Credentials(access_key, raw_credential)


__all__ = [
    "GIB",
    "MIB",
    "S3_MAX_MULTIPART_PARTS",
    "S3_MAX_MULTIPART_PART_BYTES",
    "S3_MIN_MULTIPART_PART_BYTES",
    "TIB",
    "S3Config",
    "S3Credentials",
    "credentials_from_secrets",
]
