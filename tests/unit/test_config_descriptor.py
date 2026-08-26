# SPDX-License-Identifier: Apache-2.0
"""Configuration, credential, and capability declaration tests."""

from __future__ import annotations

import pytest
from meridian_storage.object_common import (
    GUARANTEE_RETENTION_ENFORCEMENT,
    GUARANTEE_SIGNED_REFERENCE,
)
from meridian_storage.spi import SecretValue

from meridian_storage.adapters.s3 import S3Config, S3Credentials, s3_descriptor
from meridian_storage.adapters.s3.config import credentials_from_secrets


def test_config_is_closed_and_requires_explicit_insecure_http() -> None:
    with pytest.raises(ValueError, match="HTTP endpoints"):
        S3Config(bucket="valid-bucket", endpoint_url="http://localhost:9000")
    with pytest.raises(ValueError, match="without credentials"):
        S3Config(bucket="valid-bucket", endpoint_url="https://user:pass@example.com")
    with pytest.raises(ValueError, match="bucket"):
        S3Config(bucket="x")
    with pytest.raises(ValueError, match="dot path"):
        S3Config(bucket="valid-bucket", prefix="safe/../unsafe")
    config = S3Config(
        bucket="valid-bucket",
        endpoint_url="http://127.0.0.1:9000",
        allow_insecure_http=True,
    )
    assert config.namespace_root == ""
    assert config.engine_profile == "s3-compatible"


def test_credentials_are_redacted_and_support_session_json() -> None:
    credentials = credentials_from_secrets(
        SecretValue(b"access-key"),
        SecretValue(b'{"secretAccessKey":"secret-key","sessionToken":"token"}'),
    )
    assert credentials == S3Credentials("access-key", "secret-key", "token")
    assert "secret-key" not in repr(credentials)
    assert "access-key" not in repr(credentials)
    with pytest.raises(ValueError, match="unknown fields"):
        credentials_from_secrets(
            SecretValue(b"access-key"),
            SecretValue(b'{"secretAccessKey":"secret-key","endpoint":"leak"}'),
        )


def test_descriptor_is_deterministic_and_retention_is_probe_selectable() -> None:
    plain = S3Config(bucket="valid-bucket")
    locked = S3Config(bucket="valid-bucket", object_lock_mode="governance")
    first = s3_descriptor(plain)
    assert first.to_dict() == s3_descriptor(plain).to_dict()
    assert first.fingerprint == s3_descriptor(plain).fingerprint
    plain_put = first.capability_for("meridian.object.put")
    locked_put = s3_descriptor(locked).capability_for("meridian.object.put")
    assert plain_put is not None
    assert locked_put is not None
    assert GUARANTEE_RETENTION_ENFORCEMENT not in plain_put.guarantees
    assert GUARANTEE_RETENTION_ENFORCEMENT in locked_put.guarantees
    signed_get = s3_descriptor(plain, signed_references=True).capability_for("meridian.object.get")
    assert signed_get is not None
    assert GUARANTEE_SIGNED_REFERENCE in signed_get.guarantees
