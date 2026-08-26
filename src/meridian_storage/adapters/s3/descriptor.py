# SPDX-License-Identifier: Apache-2.0
"""Deterministic S3 Adapter descriptor and authenticated capability manifest."""

from __future__ import annotations

from meridian_storage.object_common import (
    GUARANTEE_BOUNDED_PREFIX_LIST,
    GUARANTEE_CONDITIONAL_CREATE,
    GUARANTEE_DIGEST_SHA256,
    GUARANTEE_DIGEST_VERIFICATION,
    GUARANTEE_EXACT_VERSION_DELETE,
    GUARANTEE_IMMUTABILITY_INTENT,
    GUARANTEE_METADATA_AFTER_COMMIT,
    GUARANTEE_MULTIPART,
    GUARANTEE_RANGE_READ,
    GUARANTEE_RETENTION_ENFORCEMENT,
    GUARANTEE_RETENTION_INTENT,
    GUARANTEE_SIGNED_REFERENCE,
    GUARANTEE_STREAMING,
    LIMIT_MAX_LIST_PAGE_SIZE,
    LIMIT_MAX_MULTIPART_PART_BYTES,
    LIMIT_MAX_MULTIPART_PARTS,
    LIMIT_MAX_OBJECT_BYTES,
    LIMIT_MAX_RANGE_BYTES,
    LIMIT_MAX_USER_METADATA_ENTRIES,
    OBJECT_OPERATION_VERSION,
)
from meridian_storage.spi import AdapterDescriptor, CapabilityManifest, OperationCapability

from ._version import __version__
from .config import S3_MAX_MULTIPART_PART_BYTES, S3_MAX_MULTIPART_PARTS, S3Config

S3_ADAPTER_ID = "s3"
S3_ADAPTER_CONTRACT_VERSION = "1.0.0"


def _capability(
    method: str,
    *,
    guarantees: tuple[str, ...] = (),
    limits: dict[str, int] | None = None,
    cursor: str = "none",
) -> OperationCapability:
    return OperationCapability(
        operation_contract=f"meridian.object.{method}",
        operation_versions=(OBJECT_OPERATION_VERSION,),
        guarantees=guarantees,
        limits=limits or {},
        cursor_behavior=cursor,
        migration_behavior="externally-orchestrated-forward",
        health_probes=("authenticated", "bucket-access"),
        extensions={"catalog": "object", "provider": "s3"},
    )


def s3_descriptor(
    config: S3Config,
    *,
    signed_references: bool = False,
) -> AdapterDescriptor:
    put_guarantees = [
        GUARANTEE_CONDITIONAL_CREATE,
        GUARANTEE_DIGEST_SHA256,
        GUARANTEE_DIGEST_VERIFICATION,
        GUARANTEE_IMMUTABILITY_INTENT,
        GUARANTEE_METADATA_AFTER_COMMIT,
        GUARANTEE_MULTIPART,
        GUARANTEE_RETENTION_INTENT,
        GUARANTEE_STREAMING,
    ]
    if config.retention_enforcement:
        put_guarantees.append(GUARANTEE_RETENTION_ENFORCEMENT)
    reference_guarantees = [GUARANTEE_DIGEST_VERIFICATION, GUARANTEE_STREAMING]
    if signed_references:
        reference_guarantees.append(GUARANTEE_SIGNED_REFERENCE)
    range_guarantees = [GUARANTEE_DIGEST_VERIFICATION, GUARANTEE_RANGE_READ]
    if signed_references:
        range_guarantees.append(GUARANTEE_SIGNED_REFERENCE)
    limits = {
        LIMIT_MAX_OBJECT_BYTES: config.max_object_bytes,
        LIMIT_MAX_USER_METADATA_ENTRIES: 128,
        LIMIT_MAX_MULTIPART_PARTS: S3_MAX_MULTIPART_PARTS,
        LIMIT_MAX_MULTIPART_PART_BYTES: S3_MAX_MULTIPART_PART_BYTES,
    }
    capabilities = (
        _capability("publish_schema"),
        _capability("create_resource"),
        _capability("put", guarantees=tuple(put_guarantees), limits=limits),
        _capability("get", guarantees=tuple(reference_guarantees)),
        _capability("stat", guarantees=(GUARANTEE_SIGNED_REFERENCE,) if signed_references else ()),
        _capability(
            "read_range",
            guarantees=tuple(range_guarantees),
            limits={LIMIT_MAX_RANGE_BYTES: config.max_range_bytes},
        ),
        _capability(
            "list",
            guarantees=(GUARANTEE_BOUNDED_PREFIX_LIST,),
            limits={LIMIT_MAX_LIST_PAGE_SIZE: 1000},
            cursor="opaque-logical-start-after",
        ),
        _capability("delete", guarantees=(GUARANTEE_EXACT_VERSION_DELETE,)),
    )
    return AdapterDescriptor(
        adapter_id=S3_ADAPTER_ID,
        adapter_contract_version=S3_ADAPTER_CONTRACT_VERSION,
        driver="boto3>=1.40,<2",
        supported_engine_versions={
            "aws-s3": ("2006-03-01",),
            "s3-compatible": ("2006-03-01",),
        },
        capabilities=capabilities,
    )


def s3_capability_manifest(
    config: S3Config,
    *,
    signed_references: bool = False,
    versioning_verified: bool = False,
    object_lock_verified: bool = False,
) -> CapabilityManifest:
    descriptor = s3_descriptor(config, signed_references=signed_references)
    return CapabilityManifest(
        descriptor=descriptor,
        engine_profile=config.engine_profile,
        engine_version=config.engine_version,
        extensions={
            "adapterVersion": __version__,
            "objectCommonVersion": "1.0.0",
            "objectLockVerified": object_lock_verified,
            "versioningVerified": versioning_verified,
        },
    )


__all__ = [
    "S3_ADAPTER_CONTRACT_VERSION",
    "S3_ADAPTER_ID",
    "s3_capability_manifest",
    "s3_descriptor",
]
