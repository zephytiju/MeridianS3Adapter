# SPDX-License-Identifier: Apache-2.0
"""Meridian Core SPI lifecycle and factory conformance tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import boto3
import pytest
from meridian_storage.object_common import (
    ObjectCapabilityMismatch,
    ObjectCatalogProvider,
    ObjectInvalidRequest,
)
from meridian_storage.runtime.config import (
    BindingConfig,
    ClientPolicy,
    SecretReference,
    TLSPolicy,
)
from meridian_storage.spi import (
    AdapterCreateContext,
    PhysicalResource,
    SecretValue,
)
from meridian_storage.testing import AdapterConformanceTarget, run_adapter_conformance
from moto import mock_aws

from meridian_storage import OperationContext, ResourceRef
from meridian_storage.adapters.s3 import S3AdapterFactory, S3Config, s3_capability_manifest

_FINGERPRINT = "sha256:" + "0" * 64


def _binding(
    *,
    tls_mode: str = "disabled",
    settings: dict[str, object] | None = None,
    adapter_id: str = "s3",
    endpoint: str | None = "http://127.0.0.1:9000",
) -> BindingConfig:
    selected_settings = {} if settings is None else dict(settings)
    if endpoint is not None and endpoint.startswith("http://"):
        selected_settings.setdefault("allowInsecureHttp", True)
    config = S3Config(
        bucket="meridian-test-bucket",
        prefix="core",
        endpoint_url=endpoint,
        allow_insecure_http=bool(selected_settings.get("allowInsecureHttp", False)),
        engine_profile="s3-compatible",
        engine_version="2006-03-01",
        require_versioning=bool(selected_settings.get("requireVersioning", False)),
    )
    manifest = s3_capability_manifest(
        config,
        versioning_verified=bool(selected_settings.get("requireVersioning", False)),
    )
    ca_ref = SecretReference("test", "ca") if tls_mode in {"server", "mutual"} else None
    client_ref = SecretReference("test", "client") if tls_mode == "mutual" else None
    return BindingConfig(
        id="object-s3",
        adapter_id=adapter_id,
        adapter_contract="1.0.0",
        engine_profile="s3-compatible",
        engine_version="2006-03-01",
        endpoint=endpoint,
        service_ref=None if endpoint is not None else "platform:s3",
        physical_namespace="meridian-test-bucket/core",
        tls=TLSPolicy(
            tls_mode,
            None if tls_mode == "disabled" else "s3.example.test",
            ca_ref,
            client_ref,
        ),
        identity_ref=SecretReference("test", "identity"),
        secret_ref=SecretReference("test", "credential"),
        client=ClientPolicy(1, 4, 1_000, 10_000, 30_000, 1_000_000, 30_000),
        required_capability_fingerprint=manifest.fingerprint,
        required_physical_fingerprint=None,
        compatibility_pins={"adapterContract": "1.0.0", "engineVersion": "2006-03-01"},
        settings=selected_settings,
        extensions={},
    )


def _context(binding: BindingConfig, *, ca: bytes | None = None) -> AdapterCreateContext:
    return AdapterCreateContext(
        binding,
        SecretValue(b"test-access"),
        SecretValue(b"test-secret"),
        None if ca is None else SecretValue(ca),
    )


def _resource_operation() -> tuple[ResourceRef, object]:
    provider = ObjectCatalogProvider()
    expression = provider.create_surface().create_resource(
        namespace="core",
        name="objects",
        profile={
            "kind": "object",
            "profile": "object",
            "mutability": "immutable",
            "rangeReads": True,
            "conditionalCreate": True,
            "boundedPrefixList": True,
            "metadata": {},
        },
    )
    return ResourceRef("object", "core", "objects"), provider.normalize(expression)


def _client() -> Any:
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="test-access",
        aws_secret_access_key="test-secret",
    )
    client.create_bucket(Bucket="meridian-test-bucket")
    return client


def test_released_core_adapter_conformance() -> None:
    with mock_aws():
        client = _client()
        binding = _binding()
        resource, operation = _resource_operation()
        factory = S3AdapterFactory(client_factory=lambda config, credentials, verify: client)
        report = run_adapter_conformance(
            AdapterConformanceTarget(
                factory=factory,
                create_context=_context(binding),
                resources=(PhysicalResource(resource, _FINGERPRINT, None, "object"),),
                operation=operation,
                context=OperationContext("principal:test"),
                assert_result=lambda result: result.data["resource"] == resource.to_dict(),
            )
        )
        assert report.checks == (
            "authenticated-open",
            "deterministic-capability-manifest",
            "deterministic-physical-verification",
            "normalized-execution",
        )
        assert report.adapter_id == "s3"


def test_runtime_state_guards_nontransactional_session_and_physical_validation() -> None:
    with mock_aws():
        client = _client()
        runtime = S3AdapterFactory(
            client_factory=lambda config, credentials, verify: client
        ).create(_context(_binding()))
        with pytest.raises(ObjectInvalidRequest, match="not open"):
            _ = runtime.adapter
        with pytest.raises(ObjectInvalidRequest, match="not open"):
            runtime.probe()
        with pytest.raises(ObjectInvalidRequest, match="not open"):
            runtime.verify_physical(())
        with pytest.raises(ObjectInvalidRequest, match="not open"):
            runtime.open_session(transactional=False)
        runtime.open()
        runtime.open()  # idempotent lifecycle open
        assert runtime.probe().evidence["bucketAccess"] == "verified"
        with pytest.raises(ObjectCapabilityMismatch, match="not transactional"):
            runtime.open_session(transactional=True)
        bad_resource = PhysicalResource(
            ResourceRef("cache", "core", "objects"), _FINGERPRINT, None, "cache"
        )
        with pytest.raises(ObjectInvalidRequest, match="only Object"):
            runtime.verify_physical((bad_resource,))
        session = runtime.open_session(transactional=False)
        for action in (session.begin, session.commit, session.rollback):
            with pytest.raises(ObjectCapabilityMismatch, match="not transactional"):
                action()
        with pytest.raises(TypeError, match="ExecutionRequest"):
            session.execute(object())  # type: ignore[arg-type]
        session.close()
        with pytest.raises(ObjectInvalidRequest, match="closed"):
            session.begin()
        runtime.close()
        runtime.close()  # idempotent lifecycle close


def test_server_tls_ca_is_private_and_cleaned_on_close() -> None:
    with mock_aws():
        client = _client()
        observed: list[bool | str] = []

        def capture(config: S3Config, credentials: object, verify: bool | str) -> Any:
            observed.append(verify)
            return client

        runtime = S3AdapterFactory(client_factory=capture).create(
            _context(
                _binding(tls_mode="server", endpoint="https://s3.example.test"),
                ca=b"test-ca-material",
            )
        )
        runtime.open()
        assert len(observed) == 1
        assert isinstance(observed[0], str)
        ca_path = Path(observed[0])
        assert ca_path.read_bytes() == b"test-ca-material"
        assert ca_path.stat().st_mode & 0o777 == 0o600
        runtime.close()
        assert not ca_path.exists()


def test_open_failure_closes_transport_and_removes_private_ca() -> None:
    class FailingClient:
        closed = False

        def head_bucket(self, **request: object) -> None:
            raise RuntimeError("provider detail")

        def close(self) -> None:
            self.closed = True

    client = FailingClient()
    observed: list[str] = []

    def capture(config: S3Config, credentials: object, verify: bool | str) -> FailingClient:
        assert isinstance(verify, str)
        observed.append(verify)
        return client

    runtime = S3AdapterFactory(client_factory=capture).create(
        _context(
            _binding(tls_mode="server", endpoint="https://s3.example.test"),
            ca=b"test-ca-material",
        )
    )
    with pytest.raises(Exception, match="unclassified failure"):
        runtime.open()
    assert client.closed
    assert not Path(observed[0]).exists()


def test_factory_rejects_invalid_composition_inputs() -> None:
    with pytest.raises(ValueError, match="configured together"):
        S3AdapterFactory(signed_reference_audience="reader")
    factory = S3AdapterFactory()
    with pytest.raises(TypeError, match="AdapterCreateContext"):
        factory.create(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires an s3 Binding"):
        factory.create(_context(_binding(adapter_id="other")))
    unresolved = replace(_binding(), endpoint=None, service_ref="platform:s3")
    with pytest.raises(ValueError, match="resolved to an endpoint"):
        factory.create(_context(unresolved))
    mutual = _context(_binding(tls_mode="mutual"), ca=b"ca")
    with pytest.raises(ObjectInvalidRequest, match="mutual TLS"):
        factory.create(mutual)
    with pytest.raises(ObjectInvalidRequest, match="disabled TLS"):
        factory.create(_context(_binding(endpoint="https://s3.example.test")))
    with pytest.raises(ObjectInvalidRequest, match="server TLS requires"):
        factory.create(_context(_binding(tls_mode="server"), ca=b"ca"))
    with pytest.raises(ObjectInvalidRequest, match="resolved CA"):
        factory.create(_context(_binding(tls_mode="server", endpoint="https://s3.example.test")))
