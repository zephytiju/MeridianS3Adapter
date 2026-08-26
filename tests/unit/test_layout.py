# SPDX-License-Identifier: Apache-2.0
"""Physical layout and cursor confidentiality tests."""

import pytest
from meridian_storage.object_common import ObjectInvalidRequest

from meridian_storage import ResourceRef
from meridian_storage.adapters.s3 import S3Config
from meridian_storage.adapters.s3.layout import ListCursor, S3Layout


def test_layout_bounds_long_ids_and_hides_logical_and_deployment_values() -> None:
    config = S3Config(bucket="private-bucket", prefix="private/prefix")
    layout = S3Layout(config)
    resource = ResourceRef("object", "namespace", "resource")
    object_id = "logical/" + "界" * 330
    digest = "sha256:" + "a" * 64
    for key in (
        layout.blob_key(resource, object_id, digest),
        layout.reference_key(resource, object_id, digest),
        layout.latest_key(resource, object_id),
    ):
        assert len(key.encode()) < 1024
        assert object_id not in key
        assert "private-bucket" not in key
    assert layout.blob_key(resource, object_id, digest) == layout.blob_key(
        resource, object_id, digest
    )


def test_cursor_round_trip_is_bounded_and_rejects_malformed_input() -> None:
    cursor = ListCursor("abc/def.json").encode()
    assert ListCursor.decode(cursor) == ListCursor("abc/def.json")
    with pytest.raises(ObjectInvalidRequest):
        ListCursor.decode("not base64!")
    with pytest.raises(ObjectInvalidRequest):
        ListCursor.decode(ListCursor("missing-slash").encode())
