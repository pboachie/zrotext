"""Prepare Docker's documented Hub cache config for the hosted image-scan job.

Keep canonical image references so Buildx retains its Moby trust policy. Google
does not guarantee cache retention; Docker falls back to Hub on a cache miss.
This prepares a private runner-temp file; the workflow validates and installs it.
"""

import json
import os
from pathlib import Path
import sys


MIRROR = "https://mirror.gcr.io"


def mirror_config(config):
    if not isinstance(config, dict):
        raise ValueError("Docker daemon configuration must be an object")
    mirrors = config.get("registry-mirrors", [])
    if not isinstance(mirrors, list) or any(
        not isinstance(value, str) or not value for value in mirrors
    ):
        raise ValueError("Docker registry mirrors must be nonempty strings")
    return dict(config, **{"registry-mirrors": [MIRROR] + [
        value for value in mirrors if value != MIRROR
    ]})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Docker configuration key")
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("Nonstandard Docker JSON constant")


def prepare_config(environment, platform):
    if platform != "linux" or any(environment.get(key) != value for key, value in (
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_OS", "Linux"),
    )):
        raise ValueError("An ephemeral hosted Linux Actions runner is required")
    temporary = Path(environment["RUNNER_TEMP"])
    if not temporary.is_absolute() or not temporary.is_dir():
        raise ValueError("An existing absolute runner temporary directory is required")
    source = Path("/etc/docker/daemon.json")
    config = json.loads(source.read_text(), object_pairs_hook=unique_object,
                        parse_constant=invalid_constant) if source.exists() else {}
    prepared = mirror_config(config)
    destination = temporary / "zrotext-docker-daemon.json"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(prepared, output, indent=2)
        output.write("\n")


def main():
    try:
        prepare_config(os.environ, sys.platform)
    except (OSError, ValueError, KeyError):
        print("Docker mirror configuration refused; inputs withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
