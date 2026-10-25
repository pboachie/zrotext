# SPDX-License-Identifier: AGPL-3.0-only
"""Prepare a per-job JSSE-only trust copy; never alter the installed JDK store."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import check_java_toolchain as java


def tool_options(existing, store, store_type):
    if any(character in existing for character in "\r\n\0"):
        raise ValueError("Multiline Java tool options are unqualified")
    properties = java.trust_properties(store, store_type)
    if any(any(character in value for character in '\"\r\n\0') for value in properties.values()):
        raise ValueError("Job-local trust path cannot be represented safely in Java tool options")
    options = " ".join(f'"-D{key}={value}"' for key, value in properties.items())
    return (existing + " " + options).strip()


def prepare(major, distribution="temurin"):
    if java.TRUST_MANIFEST_ENV in os.environ:
        raise ValueError("Pre-existing trust-copy selection must not be overwritten")
    home, executable, _, version = java.selected_runtime(major, distribution=distribution)
    try:
        temporary_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        environment_file = Path(os.environ["GITHUB_ENV"])
        if (environment_file.is_symlink() or not environment_file.is_file()
                or not environment_file.resolve().is_relative_to(temporary_root)):
            raise ValueError("GitHub environment output must be an ordinary per-job file")
    except (KeyError, OSError) as error:
        raise ValueError("A GitHub job-local temporary directory and environment output are required") from error

    source = home / "lib/security/cacerts"
    source_digest = java.file_digest(source)
    security = java.vendor_security(home)
    store_type, original = java.inventory(java.probe(executable, "inventory", source))
    expected = java.retained_certificates(original)
    if not expected:
        raise ValueError("Filtering must retain other trusted certificates")
    # A new private directory prevents overwriting any pre-existing file or store.
    directory = Path(tempfile.mkdtemp(prefix=java.TRUST_DIRECTORY_PREFIX, dir=temporary_root))
    store = directory / "cacerts"
    copy_type, copied = java.inventory(java.probe(executable, "filter", source, store,
                                               ",".join(sorted(java.IMPACTED_ROOTS))))
    if copy_type != store_type or copied != expected:
        raise ValueError("A non-target alias, certificate, entry type or attribute changed")
    java.verify_roots(java.fingerprints(copied))
    if java.file_digest(source) != source_digest:
        raise ValueError("The installed trust store changed during copy preparation")

    copy_digest = java.file_digest(store)
    options = tool_options(os.environ.get("JAVA_TOOL_OPTIONS", ""), store, store_type)
    qualified_environment = dict(os.environ, JAVA_TOOL_OPTIONS=options)
    java.verify_effective(java.probe(executable, "effective", env=qualified_environment), store, copied)
    if (java.file_digest(source) != source_digest or java.file_digest(store) != copy_digest
            or java.vendor_security(home) != security):
        raise ValueError("The trust stores or vendor security policy changed during effective-trust verification")
    manifest = {"schema": 2, "java_home": str(home), "source_sha256": source_digest,
                "copy_sha256": copy_digest, "store_type": store_type,
                "source_inventory": original, "copy_inventory": copied, "vendor_security": security}
    manifest_path = directory / "trust.json"
    with manifest_path.open("x", encoding="utf-8") as output:
        json.dump(manifest, output, sort_keys=True)
        output.write("\n")
    # Export only after qualification; later CI processes inherit this TLS-only
    # override. Default vendor algorithm/blocklist files remain untouched.
    with environment_file.open("a", encoding="utf-8") as output:
        output.write(f"JAVA_TOOL_OPTIONS={options}\n{java.TRUST_MANIFEST_ENV}={manifest_path}\n")
    removed = len(original) - len(copied)
    print(f"{distribution} {version}: qualified job-local JSSE copy; removed {removed} impacted aliases; "
          "all other aliases/certificates/entry attributes and the installed store are unchanged")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=sorted(java.MINIMUM_VERSIONS), required=True)
    parser.add_argument("--distribution", choices=sorted(java.DISTRIBUTIONS), default="temurin")
    args = parser.parse_args(argv)
    try:
        prepare(args.major, args.distribution)
    except (ValueError, OSError) as error:
        # Do not expose paths, environment variables or certificate inventories.
        print(str(error) if isinstance(error, ValueError) else "Job-local trust copy could not be prepared", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
