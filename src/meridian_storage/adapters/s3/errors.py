# SPDX-License-Identifier: Apache-2.0
"""Normalize SDK and S3 failures into the released Object error taxonomy."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ParamValidationError,
    ReadTimeoutError,
)
from meridian_storage.errors import MeridianError
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

_AUTHENTICATION = {
    "AuthorizationHeaderMalformed",
    "ExpiredToken",
    "InvalidAccessKeyId",
    "InvalidToken",
    "SignatureDoesNotMatch",
    "TokenRefreshRequired",
}
_NOT_FOUND = {"404", "NoSuchBucket", "NoSuchKey", "NoSuchUpload", "NotFound"}
_CONFLICT = {"409", "ConditionalRequestConflict", "PreconditionFailed"}
_RATE_LIMIT = {"RequestLimitExceeded", "SlowDown", "Throttling", "ThrottlingException"}
_QUOTA = {"EntityTooLarge", "InsufficientStorage", "QuotaExceeded", "StorageFull"}
_CORRUPTION = {"BadDigest", "ChecksumMismatch", "InvalidDigest"}


def normalize_s3_error(
    error: BaseException,
    *,
    operation: str,
    retention_sensitive: bool = False,
) -> MeridianError:
    """Return a stable safe failure without copying provider text or configuration."""

    if isinstance(error, MeridianError):
        return error
    if isinstance(error, ClientError):
        response = error.response
        raw_error = response.get("Error", {})
        code = str(raw_error.get("Code", "Unknown"))
        status = str(response.get("ResponseMetadata", {}).get("HTTPStatusCode", ""))
        operation_contract = (
            f"meridian.object.{operation}"
            if operation in {"delete", "get", "list", "put", "read_range", "stat"}
            else None
        )
        details: dict[str, Any] = {
            "operation_contract": operation_contract,
            "adapter_provenance": {"adapterId": "s3"},
        }
        if code in _AUTHENTICATION:
            return ObjectAuthenticationFailed(**details)
        if code in _NOT_FOUND or status == "404":
            return ObjectNotFound(**details)
        if code in _CONFLICT or status == "412":
            return ConditionalConflict(**details)
        if code == "InvalidRange" or status == "416":
            return RangeNotSatisfiable(**details)
        if code in _RATE_LIMIT or status == "429":
            return ObjectRateLimited(**details)
        if code in _QUOTA or status == "507":
            return ObjectQuotaExceeded(**details)
        if code in _CORRUPTION:
            return DigestMismatch(**details)
        if retention_sensitive and code in {
            "AccessDenied",
            "AllAccessDisabled",
            "InvalidRequest",
            "MethodNotAllowed",
        }:
            return RetentionDenied(**details)
        if code in {"AccessDenied", "AllAccessDisabled", "MethodNotAllowed"} or status == "403":
            if retention_sensitive:
                return RetentionDenied(**details)
            return ObjectAuthorizationFailed(**details)
        return ObjectUnavailable(**details)
    if isinstance(error, ParamValidationError):
        return ObjectInvalidRequest(
            "S3 Adapter generated an invalid provider request",
            adapter_provenance={"adapterId": "s3"},
        )
    if isinstance(
        error,
        (
            ConnectTimeoutError,
            ConnectionClosedError,
            EndpointConnectionError,
            ReadTimeoutError,
        ),
    ):
        return ObjectUnavailable(adapter_provenance={"adapterId": "s3"})
    if isinstance(error, BotoCoreError):
        return ObjectUnavailable(adapter_provenance={"adapterId": "s3"})
    return ObjectUnavailable(
        "S3 Adapter returned an unclassified failure",
        adapter_provenance={"adapterId": "s3"},
    )


def raise_normalized_s3_error(
    error: BaseException,
    *,
    operation: str,
    retention_sensitive: bool = False,
) -> None:
    raise normalize_s3_error(
        error,
        operation=operation,
        retention_sensitive=retention_sensitive,
    ) from error


__all__ = ["normalize_s3_error", "raise_normalized_s3_error"]
