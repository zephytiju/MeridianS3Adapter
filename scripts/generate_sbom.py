#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate a deterministic SPDX 2.3 JSON SBOM for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

NAME = "meridian-storage-s3"
VERSION = "1.0.1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("artifacts", nargs="+", type=Path)
    arguments = parser.parse_args()
    artifacts = sorted(arguments.artifacts, key=lambda path: path.name)
    checksums = {path.name: sha256(path) for path in artifacts}
    namespace_digest = hashlib.sha256(
        json.dumps(checksums, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    files: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package",
        }
    ]
    for index, path in enumerate(artifacts, start=1):
        identifier = f"SPDXRef-Artifact-{index}"
        files.append(
            {
                "SPDXID": identifier,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksums[path.name]}],
                "copyrightText": "NOASSERTION",
                "fileName": path.name,
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "GENERATES",
                "relatedSpdxElement": identifier,
            }
        )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {NAME}/generate_sbom.py-{VERSION}"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://github.com/zephytiju/{NAME}/sbom/{namespace_digest}",
        "files": files,
        "name": f"{NAME}-{VERSION}-release",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "copyrightText": "Copyright 2026 Meridian contributors",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": f"pkg:pypi/{NAME}@{VERSION}",
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": NAME,
                "supplier": "Organization: Meridian contributors",
                "versionInfo": VERSION,
            }
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
