# SPDX-License-Identifier: Apache-2.0
"""Stable provider failure normalization tests."""

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, ParamValidationError
from meridian_storage.object_common import (
    ConditionalConflict,
    DigestMismatch,
    ObjectAuthenticationFailed,
    ObjectAuthorizationFailed,
    ObjectInvalidRequest,
    ObjectNotFound,
    ObjectQuotaExceeded,
    ObjectRateLimited,
    ObjectUnavailable,
    RangeNotSatisfiable,
    RetentionDenied,
)

from meridian_storage.adapters.s3.errors import normalize_s3_error


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("InvalidAccessKeyId", ObjectAuthenticationFailed),
        ("NoSuchKey", ObjectNotFound),
        ("PreconditionFailed", ConditionalConflict),
        ("InvalidRange", RangeNotSatisfiable),
        ("SlowDown", ObjectRateLimited),
        ("QuotaExceeded", ObjectQuotaExceeded),
        ("BadDigest", DigestMismatch),
        ("AccessDenied", ObjectAuthorizationFailed),
        ("UnknownVendorFailure", ObjectUnavailable),
    ],
)
def test_client_error_mapping(code: str, expected: type[Exception]) -> None:
    source = ClientError(
        {"Error": {"Code": code, "Message": "must not escape"}, "ResponseMetadata": {}},
        "GetObject",
    )
    result = normalize_s3_error(source, operation="get")
    assert isinstance(result, expected)
    assert "must not escape" not in str(result)
    assert result.adapter_provenance["adapterId"] == "s3"


def test_retention_sensitive_access_denied_and_transport_failures() -> None:
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "provider"}}, "DeleteObject")
    assert isinstance(
        normalize_s3_error(denied, operation="delete", retention_sensitive=True),
        RetentionDenied,
    )
    worm_protected = ClientError(
        {"Error": {"Code": "InvalidRequest", "Message": "provider"}}, "DeleteObject"
    )
    assert isinstance(
        normalize_s3_error(
            worm_protected,
            operation="delete",
            retention_sensitive=True,
        ),
        RetentionDenied,
    )
    assert isinstance(
        normalize_s3_error(
            EndpointConnectionError(endpoint_url="https://private"), operation="get"
        ),
        ObjectUnavailable,
    )
    assert isinstance(
        normalize_s3_error(ParamValidationError(report="unsafe detail"), operation="put"),
        ObjectInvalidRequest,
    )
