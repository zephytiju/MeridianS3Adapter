# SPDX-License-Identifier: Apache-2.0
"""Release SBOM identity and checksums must describe the owning artifacts."""

import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path


def test_sbom_matches_project_version_and_artifact_hashes(tmp_path):
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    artifact = tmp_path / f"meridian_storage_s3-{project['version']}-py3-none-any.whl"
    artifact.write_bytes(b"deterministic-test-artifact")
    output = tmp_path / "sbom.json"
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts/generate_sbom.py"),
            "--output",
            str(output),
            str(artifact),
        ],
        check=True,
    )
    document = json.loads(output.read_text())
    package = document["packages"][0]
    assert package["name"] == project["name"]
    assert package["versionInfo"] == project["version"]
    assert (
        package["externalRefs"][0]["referenceLocator"]
        == f"pkg:pypi/{project['name']}@{project['version']}"
    )
    assert document["files"][0]["checksums"] == [
        {"algorithm": "SHA256", "checksumValue": hashlib.sha256(artifact.read_bytes()).hexdigest()}
    ]
    first = output.read_bytes()
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts/generate_sbom.py"),
            "--output",
            str(output),
            str(artifact),
        ],
        check=True,
    )
    assert output.read_bytes() == first
