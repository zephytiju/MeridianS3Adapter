# SPDX-License-Identifier: Apache-2.0
"""Authenticated, non-provisioning S3 health and capability probes."""

from __future__ import annotations

from dataclasses import dataclass

from meridian_storage.object_common import ObjectCapabilityMismatch, ObjectUnavailable
from meridian_storage.spi import AdapterProbe, CapabilityManifest

from .config import S3Config
from .descriptor import s3_capability_manifest
from .transport import S3Transport


@dataclass(frozen=True, slots=True)
class S3ProbeEvidence:
    versioning_status: str
    object_lock_enabled: bool

    @property
    def versioning_enabled(self) -> bool:
        return self.versioning_status == "Enabled"


class S3HealthProbe:
    def __init__(
        self,
        transport: S3Transport,
        config: S3Config,
        *,
        signed_references: bool = False,
    ) -> None:
        self._transport = transport
        self._config = config
        self._signed_references = signed_references

    def run(self) -> tuple[AdapterProbe, S3ProbeEvidence]:
        self._transport.head_bucket()
        versioning_status = (
            self._transport.versioning_status()
            if self._config.require_versioning or self._config.retention_enforcement
            else "NotProbed"
        )
        object_lock_enabled = (
            self._transport.object_lock_enabled() if self._config.retention_enforcement else False
        )
        if self._config.require_versioning and versioning_status != "Enabled":
            raise ObjectUnavailable("S3 bucket versioning is required but was not verified")
        if self._config.retention_enforcement and not object_lock_enabled:
            raise ObjectCapabilityMismatch(
                "S3 Object Lock enforcement was configured but not verified",
                operation_contract="meridian.object.put",
                adapter_provenance={"adapterId": "s3", "objectLockVerified": "false"},
            )
        evidence = S3ProbeEvidence(versioning_status, object_lock_enabled)
        manifest: CapabilityManifest = s3_capability_manifest(
            self._config,
            signed_references=self._signed_references,
            versioning_verified=evidence.versioning_enabled,
            object_lock_verified=evidence.object_lock_enabled,
        )
        return (
            AdapterProbe(
                manifest,
                evidence={
                    "authenticated": "true",
                    "bucketAccess": "verified",
                    "checksumHeaders": str(self._config.checksum_headers).lower(),
                    "objectLock": ("enabled" if evidence.object_lock_enabled else "not-enabled"),
                    "versioning": evidence.versioning_status,
                },
            ),
            evidence,
        )


__all__ = ["S3HealthProbe", "S3ProbeEvidence"]
