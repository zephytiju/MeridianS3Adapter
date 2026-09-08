# SPDX-License-Identifier: Apache-2.0
"""S3 API identity stays distinct from independently selected server releases."""

import json
from dataclasses import replace
from importlib.metadata import version

import pytest
from meridian_storage.runtime.config import BindingConfig
from meridian_storage.semantics import sha256_fingerprint

from meridian_storage.adapters.s3 import S3Config, s3_capability_manifest, s3_descriptor
from meridian_storage.adapters.s3.probe import S3HealthProbe
from tests.unit.test_factory_runtime import _binding, _context
from tests.unit.test_migration_probe import _ProbeTransport


@pytest.mark.parametrize("profile", ["aws-s3", "s3-compatible"])
@pytest.mark.parametrize("release", [None, "RELEASE.2025-04-22T22-12-26Z", "unlisted-server-build"])
def test_release_selection_is_provenance_and_never_an_observation(profile, release):
    config = S3Config(
        bucket="valid-bucket", engine_profile=profile, selected_server_version=release
    )
    probe, _ = S3HealthProbe(_ProbeTransport(), config).run()
    manifest = probe.manifest
    assert manifest.engine_version == "2006-03-01"
    assert manifest.extensions["s3ApiContract"] == "2006-03-01"
    assert manifest.extensions["selectedServerVersion"] == release
    assert manifest.extensions["objectCommonVersion"] == version("meridian-storage-object-common")
    assert manifest.extensions["coreVersion"] == version("meridian-storage-core")
    assert probe.observed_engine_version is None
    assert probe.evidence["serverVersionObservation"] == "unavailable"
    assert sha256_fingerprint(json.loads(json.dumps(manifest.to_dict()))) == manifest.fingerprint
    assert (
        s3_descriptor(config).fingerprint
        == s3_descriptor(replace(config, selected_server_version="another-build")).fingerprint
    )


def test_selected_release_round_trip_and_deployment_fingerprint():
    binding = _binding(settings={"selectedServerVersion": "unlisted-server-build"})
    restored = BindingConfig.from_mapping(json.loads(json.dumps(binding.to_dict())), "binding")
    config = S3Config.from_create_context(_context(restored))
    assert config.selected_server_version == "unlisted-server-build"
    assert restored.to_dict() == binding.to_dict()
    assert (
        s3_capability_manifest(config).fingerprint
        != s3_capability_manifest(
            replace(config, selected_server_version="another-build")
        ).fingerprint
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"engine_version": "RELEASE.2030-01-01"}, "API contract"),
        ({"engine_version": "2005-01-01"}, "API contract"),
        ({"engine_profile": "invented-provider"}, "profile"),
        ({"selected_server_version": ""}, "bounded"),
        ({"selected_server_version": "unsafe\nrelease"}, "bounded"),
        ({"selected_server_version": "x" * 257}, "bounded"),
    ],
)
def test_contract_and_metadata_negative_checks_remain(changes, reason):
    with pytest.raises(ValueError, match=reason):
        S3Config(bucket="valid-bucket", **changes)


def test_committed_manifest_golden_content_and_deployment_drift():
    from pathlib import Path

    from meridian_storage.spi._validation import validate_binding_probe

    from meridian_storage import CompatibilityError

    fixtures = json.loads(
        (Path(__file__).parents[2] / "evidence/release-provenance.v1.json").read_text()
    )
    for fixture in fixtures:
        profile = fixture["manifest"]["engineProfile"]
        manifest = s3_capability_manifest(
            S3Config(
                bucket="valid-bucket",
                engine_profile=profile,
                selected_server_version="unlisted-server-build",
            )
        )
        assert manifest.to_dict() == fixture["manifest"]
        assert manifest.fingerprint == fixture["fingerprint"]

    config = S3Config(
        bucket="meridian-test-bucket", prefix="core", selected_server_version="build-a"
    )
    probe, _ = S3HealthProbe(_ProbeTransport(), config).run()
    binding = replace(_binding(), required_capability_fingerprint=probe.manifest.fingerprint)
    validate_binding_probe(binding, probe)
    changed, _ = S3HealthProbe(
        _ProbeTransport(), replace(config, selected_server_version="build-b")
    ).run()
    with pytest.raises(CompatibilityError, match="fingerprint"):
        validate_binding_probe(binding, changed)
    locked = replace(binding, compatibility_pins={"observedEngineVersion": "build-a"})
    with pytest.raises(CompatibilityError, match="observedEngineVersion"):
        validate_binding_probe(locked, probe)
