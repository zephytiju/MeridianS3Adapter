# SPDX-License-Identifier: Apache-2.0
"""Meridian Core AdapterFactory, runtime, and session integration."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from meridian_storage.object_common import (
    ObjectCapabilityMismatch,
    ObjectInvalidRequest,
    PayloadRegistry,
    ReferenceSigner,
    default_payload_registry,
)
from meridian_storage.semantics import JsonValue, sha256_fingerprint
from meridian_storage.spi import (
    AdapterCreateContext,
    AdapterProbe,
    AdapterSession,
    ExecutionRequest,
    ExecutionResult,
    PhysicalResource,
    PhysicalVerification,
)

from ._version import __version__
from .adapter import S3ObjectAdapter
from .config import S3Config, S3Credentials, credentials_from_secrets
from .descriptor import S3_ADAPTER_ID
from .migration import S3MigrationHooks
from .probe import S3HealthProbe
from .transport import S3Transport, create_s3_client

ClientFactory = Callable[[S3Config, S3Credentials, bool | str], Any]


def _default_client_factory(
    config: S3Config,
    credentials: S3Credentials,
    verify: bool | str,
) -> Any:
    return create_s3_client(config, credentials, verify=verify)


class S3AdapterSession:
    def __init__(self, runtime: S3AdapterRuntime) -> None:
        self._runtime = runtime
        self._closed = False

    def begin(self) -> None:
        self._require_open()
        raise ObjectCapabilityMismatch("S3 Object Operations are not transactional")

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self._require_open()
        if not isinstance(request, ExecutionRequest):
            raise TypeError("S3 Adapter session requires an ExecutionRequest")
        result = self._runtime.adapter.execute(
            request.operation,
            self._runtime.payloads,
            context=request.context,
        )
        manifest = self._runtime.probe().manifest
        return ExecutionResult(
            data=cast(JsonValue, result),
            result_bytes=0,
            provenance={
                "adapterId": S3_ADAPTER_ID,
                "adapterVersion": __version__,
                "capabilityFingerprint": manifest.fingerprint,
                "engineProfile": manifest.engine_profile,
                "engineVersion": manifest.engine_version,
            },
        )

    def commit(self) -> None:
        self._require_open()
        raise ObjectCapabilityMismatch("S3 Object Operations are not transactional")

    def rollback(self) -> None:
        self._require_open()
        raise ObjectCapabilityMismatch("S3 Object Operations are not transactional")

    def close(self) -> None:
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ObjectInvalidRequest("S3 Adapter session is closed")


class S3AdapterRuntime:
    def __init__(
        self,
        *,
        config: S3Config,
        credentials: S3Credentials,
        payloads: PayloadRegistry,
        client_factory: ClientFactory,
        tls_mode: str,
        tls_ca: bytes | None,
        reference_signer: ReferenceSigner | None,
        signed_reference_audience: str | None,
    ) -> None:
        self.config = config
        self.credentials = credentials
        self.payloads = payloads
        self._client_factory = client_factory
        self._tls_mode = tls_mode
        self._tls_ca = tls_ca
        self._reference_signer = reference_signer
        self._signed_reference_audience = signed_reference_audience
        self._transport: S3Transport | None = None
        self._adapter: S3ObjectAdapter | None = None
        self._probe: AdapterProbe | None = None
        self._ca_path: Path | None = None
        self._open = False

    @property
    def adapter(self) -> S3ObjectAdapter:
        if self._adapter is None:
            raise ObjectInvalidRequest("S3 Adapter runtime is not open")
        return self._adapter

    @property
    def migrations(self) -> S3MigrationHooks:
        return S3MigrationHooks(self.adapter.transport, self.adapter.layout)

    def open(self) -> None:
        if self._open:
            return
        verify: bool | str = True
        if self._tls_mode == "disabled":
            verify = False
        elif self._tls_mode == "server" and self._tls_ca is not None:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix="meridian-s3-ca-", suffix=".pem", delete=False
            ) as handle:
                handle.write(self._tls_ca)
                handle.flush()
                os.fchmod(handle.fileno(), 0o600)
            self._ca_path = Path(handle.name)
            verify = str(self._ca_path)
        client = self._client_factory(self.config, self.credentials, verify)
        self._transport = S3Transport(client, self.config)
        self._adapter = S3ObjectAdapter(
            self._transport,
            self.config,
            payloads=self.payloads,
            reference_signer=self._reference_signer,
            signed_reference_audience=self._signed_reference_audience,
        )
        try:
            probe, _ = S3HealthProbe(
                self._transport,
                self.config,
                signed_references=self._reference_signer is not None,
            ).run()
            self._probe = probe
            self._open = True
        except BaseException:
            self._transport.close()
            self._transport = None
            self._adapter = None
            self._cleanup_ca()
            raise

    def probe(self) -> AdapterProbe:
        if not self._open or self._probe is None:
            raise ObjectInvalidRequest("S3 Adapter runtime is not open")
        return self._probe

    def verify_physical(
        self,
        resources: tuple[PhysicalResource, ...],
    ) -> PhysicalVerification:
        if not self._open or self._transport is None:
            raise ObjectInvalidRequest("S3 Adapter runtime is not open")
        self._transport.head_bucket()
        mappings: dict[str, str] = {}
        evidence_resources: list[dict[str, JsonValue]] = []
        for resource in sorted(resources, key=lambda item: str(item.resource_ref)):
            if resource.resource_ref.catalog != "object":
                raise ObjectInvalidRequest("S3 physical verification accepts only Object Resources")
            opaque = hashlib.sha256(
                (f"{self.config.bucket}\0{self.config.prefix}\0{resource.resource_ref}").encode()
            ).hexdigest()
            mappings[str(resource.resource_ref)] = f"s3:sha256:{opaque}"
            evidence_resources.append(
                {
                    "resource": str(resource.resource_ref),
                    "resourceFingerprint": resource.resource_fingerprint,
                    "schemaFingerprint": resource.schema_fingerprint,
                    "profile": resource.profile,
                }
            )
        fingerprint = sha256_fingerprint(
            {
                "formatVersion": "meridian.s3-physical-verification.v1",
                "adapterId": S3_ADAPTER_ID,
                "engineProfile": self.config.engine_profile,
                "engineVersion": self.config.engine_version,
                "namespaceFingerprint": hashlib.sha256(
                    f"{self.config.bucket}\0{self.config.prefix}".encode()
                ).hexdigest(),
                "resources": evidence_resources,
            }
        )
        return PhysicalVerification(
            fingerprint=fingerprint,
            mappings=mappings,
            evidence={
                "authenticated": "true",
                "resourceCount": str(len(resources)),
            },
        )

    def open_session(self, *, transactional: bool) -> AdapterSession:
        if not self._open:
            raise ObjectInvalidRequest("S3 Adapter runtime is not open")
        if transactional:
            raise ObjectCapabilityMismatch("S3 Object Operations are not transactional")
        return S3AdapterSession(self)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
        self._transport = None
        self._adapter = None
        self._probe = None
        self._open = False
        self._cleanup_ca()

    def _cleanup_ca(self) -> None:
        if self._ca_path is not None:
            try:
                self._ca_path.unlink(missing_ok=True)
            finally:
                self._ca_path = None


class S3AdapterFactory:
    """Discoverable factory; composition may inject the provider-neutral payload registry."""

    adapter_id = S3_ADAPTER_ID

    def __init__(
        self,
        *,
        payloads: PayloadRegistry | None = None,
        client_factory: ClientFactory | None = None,
        reference_signer: ReferenceSigner | None = None,
        signed_reference_audience: str | None = None,
    ) -> None:
        self.payloads = default_payload_registry() if payloads is None else payloads
        self._client_factory = client_factory or _default_client_factory
        self._reference_signer = reference_signer
        self._signed_reference_audience = signed_reference_audience
        if (reference_signer is None) != (signed_reference_audience is None):
            raise ValueError("signed reference signer and audience must be configured together")

    def create(self, context: AdapterCreateContext) -> S3AdapterRuntime:
        if not isinstance(context, AdapterCreateContext):
            raise TypeError("S3 Adapter factory requires AdapterCreateContext")
        config = S3Config.from_create_context(context)
        credentials = credentials_from_secrets(context.identity, context.credential)
        tls_mode = context.binding.tls.mode
        if tls_mode == "mutual":
            raise ObjectInvalidRequest(
                "the boto3 S3 transport does not support mutual TLS identity"
            )
        endpoint_scheme = urlsplit(config.endpoint_url or "").scheme
        if tls_mode == "disabled" and endpoint_scheme != "http":
            raise ObjectInvalidRequest("disabled TLS requires an explicit HTTP S3 endpoint")
        if tls_mode == "server" and endpoint_scheme != "https":
            raise ObjectInvalidRequest("server TLS requires an HTTPS S3 endpoint")
        tls_ca = context.tls_ca.reveal() if context.tls_ca is not None else None
        if tls_mode == "server" and tls_ca is None:
            raise ObjectInvalidRequest("server TLS binding requires resolved CA material")
        return S3AdapterRuntime(
            config=config,
            credentials=credentials,
            payloads=self.payloads,
            client_factory=self._client_factory,
            tls_mode=tls_mode,
            tls_ca=tls_ca,
            reference_signer=self._reference_signer,
            signed_reference_audience=self._signed_reference_audience,
        )


__all__ = ["ClientFactory", "S3AdapterFactory", "S3AdapterRuntime", "S3AdapterSession"]
