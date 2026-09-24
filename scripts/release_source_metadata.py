#!/usr/bin/env python3
"""Compute nonsecret source metadata stamped into release server images."""

import json
from pathlib import Path

from release_bundle import (DEVICE_STREAM_SCHEMA, ROOT, WEB_FILES, file_set_digest,
                            migrations, sha256)


def source_metadata(root: Path = ROOT) -> dict[str, object]:
    last, migration_digest = migrations(root)
    schema = root / DEVICE_STREAM_SCHEMA
    if schema.is_symlink() or not schema.is_file():
        raise ValueError("Device-stream schema is missing or linked")
    return {
        "web_static_sha256": file_set_digest(root, WEB_FILES),
        "device_stream_protocol": "v1",
        "device_stream_schema_sha256": sha256(schema.read_bytes()),
        "migration_first": 1,
        "migration_last": last,
        "migration_source_sha256": migration_digest,
    }


if __name__ == "__main__":
    print(json.dumps(source_metadata(), sort_keys=True))
