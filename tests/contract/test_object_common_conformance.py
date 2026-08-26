# SPDX-License-Identifier: Apache-2.0
"""Released Object Common conformance is the authoritative provider-neutral gate."""

from meridian_storage.object_common import run_object_conformance


def test_released_object_common_conformance(s3_fixture: object) -> None:
    report = run_object_conformance(s3_fixture.adapter)
    report.require_success()
    assert report.passed
    assert len(report.checks) == 9
    assert report.fingerprint.startswith("sha256:")
