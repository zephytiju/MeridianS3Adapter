# SPDX-License-Identifier: Apache-2.0
"""Private physical key layout; logical references never expose these values."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass

from meridian_storage.object_common import ObjectInvalidRequest

from meridian_storage import ResourceRef

from .config import S3Config

_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")


def _token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_hex(digest: str) -> str:
    match = _DIGEST_RE.fullmatch(digest)
    if match is None:
        raise ValueError("digest must be sha256:<lowercase hex>")
    return match.group(1)


@dataclass(frozen=True, slots=True)
class ListCursor:
    last_suffix: str

    def encode(self) -> str:
        raw = json.dumps(
            {"last": self.last_suffix, "v": 1},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @classmethod
    def decode(cls, value: str) -> ListCursor:
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ObjectInvalidRequest("list cursor is invalid")
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
            parsed = json.loads(raw)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise ObjectInvalidRequest("list cursor is invalid") from exc
        if (
            not isinstance(parsed, dict)
            or set(parsed) != {"last", "v"}
            or parsed.get("v") != 1
            or not isinstance(parsed.get("last"), str)
            or len(parsed["last"]) > 1024
            or "/" not in parsed["last"]
        ):
            raise ObjectInvalidRequest("list cursor is invalid")
        return cls(parsed["last"])


class S3Layout:
    """Deterministic V1 layout with bounded keys for every valid logical Object id."""

    def __init__(self, config: S3Config) -> None:
        self._root = f"{config.namespace_root}_meridian/object/v1"

    @staticmethod
    def resource_token(resource: ResourceRef) -> str:
        return _token(str(resource))

    @staticmethod
    def object_token(object_id: str) -> str:
        return _token(object_id)

    def blob_key(self, resource: ResourceRef, object_id: str, digest: str) -> str:
        hexadecimal = _digest_hex(digest)
        return (
            f"{self._root}/objects/{self.resource_token(resource)}/"
            f"{self.object_token(object_id)}/sha256/{hexadecimal}"
        )

    def reference_key(self, resource: ResourceRef, object_id: str, digest: str) -> str:
        return (
            f"{self.reference_prefix(resource)}{self.object_token(object_id)}/"
            f"{_digest_hex(digest)}.json"
        )

    def reference_prefix(self, resource: ResourceRef) -> str:
        return f"{self._root}/refs/{self.resource_token(resource)}/"

    def latest_key(self, resource: ResourceRef, object_id: str) -> str:
        return (
            f"{self._root}/latest/{self.resource_token(resource)}/"
            f"{self.object_token(object_id)}.json"
        )

    def schema_key(self, namespace: str, name: str, version: str) -> str:
        return f"{self._root}/registry/schemas/{_token(f'{namespace}:{name}@{version}')}.json"

    def resource_key(self, resource: ResourceRef) -> str:
        return f"{self._root}/registry/resources/{self.resource_token(resource)}.json"

    def orphan_key(self, resource: ResourceRef, object_id: str, digest: str) -> str:
        return (
            f"{self._root}/orphans/{self.resource_token(resource)}/"
            f"{self.object_token(object_id)}/{_digest_hex(digest)}.json"
        )

    def deletion_evidence_key(self, resource: ResourceRef, object_id: str, digest: str) -> str:
        return (
            f"{self._root}/deletions/{self.resource_token(resource)}/"
            f"{self.object_token(object_id)}/{_digest_hex(digest)}.json"
        )

    def migration_key(self, revision: int) -> str:
        return f"{self._root}/migrations/{revision:08d}.json"

    def start_after(self, resource: ResourceRef, cursor: str | None) -> str | None:
        if cursor is None:
            return None
        parsed = ListCursor.decode(cursor)
        return f"{self.reference_prefix(resource)}{parsed.last_suffix}"

    def cursor_for_key(self, resource: ResourceRef, key: str) -> str:
        prefix = self.reference_prefix(resource)
        if not key.startswith(prefix):
            raise ValueError("reference key is outside its Resource prefix")
        return ListCursor(key[len(prefix) :]).encode()


__all__ = ["ListCursor", "S3Layout"]
