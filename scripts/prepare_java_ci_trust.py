# SPDX-License-Identifier: AGPL-3.0-only
"""Prepare a per-job JSSE-only trust copy; never alter the installed JDK store."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys
import tempfile

import check_java_toolchain as java


class EnvironmentOutput:
    """An already-open runner command file, not an arbitrary append pathname."""

    def __init__(self, root, path, descriptor):
        self.root, self.path, self.descriptor = root, path, descriptor
        self.root_identity = java.ordinary_directory(root)
        self.parent_identity = java.ordinary_directory(path.parent)
        self.identity = java.file_identity(os.fstat(descriptor))

    def verify(self, protected):
        if (java.ordinary_directory(self.root) != self.root_identity
                or java.ordinary_directory(self.path.parent) != self.parent_identity):
            raise ValueError("Runner command directory changed during qualification")
        opened, named = os.fstat(self.descriptor), self.path.lstat()
        java.validate_local_metadata(opened)
        java.validate_local_metadata(named)
        if (java.file_identity(opened) != self.identity
                or java.file_identity(named) != self.identity
                or self.path != self.path.resolve(strict=True)):
            raise ValueError("Runner command file changed during qualification")
        if any(java.file_identity(path.stat()) == self.identity for path in protected):
            raise ValueError("Runner command file aliases a protected Java artifact")

    def append(self, value, protected):
        self.verify(protected)
        data = value.encode("utf-8")
        while data:
            written = os.write(self.descriptor, data)
            if written <= 0:
                raise ValueError("Runner command file append did not complete")
            data = data[written:]
        self.verify(protected)


@contextmanager
def environment_output(root, protected):
    try:
        path = Path(os.environ["GITHUB_ENV"])
        # Current hosted-runner protocol, shared by Linux and Windows:
        # actions/runner src/Runner.Worker/FileCommandManager.cs.
        if (path.parent != root / "_runner_file_commands"
                or not re.fullmatch(r"set_env_[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", path.name)):
            raise ValueError("GitHub environment output must be the runner's per-step command file")
        java.ordinary_directory(path.parent)
        descriptor = java.open_local_file(path, os.O_WRONLY | os.O_APPEND)
    except (KeyError, OSError, RuntimeError) as error:
        raise ValueError("An existing ordinary GitHub environment command file is required") from error
    try:
        output = EnvironmentOutput(root, path, descriptor)
        output.verify(protected)
        yield output
    finally:
        os.close(descriptor)


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
    temporary_root = java.runner_temporary_root()
    source = home / "lib/security/cacerts"
    protected = [source, home / "conf/security/java.security", home / "lib/security/blocked.certs"]
    with environment_output(temporary_root, protected) as output:
        source_digest = java.file_digest(source)
        security = java.vendor_security(home)
        store_type, original = java.inventory(java.probe(executable, "inventory", source))
        expected = java.retained_certificates(original)
        if not expected:
            raise ValueError("Filtering must retain other trusted certificates")
        # A new private directory prevents overwriting any pre-existing file or store.
        directory = Path(tempfile.mkdtemp(prefix=java.TRUST_DIRECTORY_PREFIX, dir=temporary_root))
        parent_identity = java.artifact_parent(temporary_root, directory)
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
        if java.artifact_parent(temporary_root, directory) != parent_identity:
            raise ValueError("Trust artifact directory changed during preparation")
        with manifest_path.open("x", encoding="utf-8") as manifest_file:
            json.dump(manifest, manifest_file, sort_keys=True)
            manifest_file.write("\n")
        if java.artifact_parent(temporary_root, directory) != parent_identity:
            raise ValueError("Trust artifact directory changed during manifest creation")
        # Export only after qualification; later CI processes inherit this TLS-only
        # override. Default vendor algorithm/blocklist files remain untouched.
        output.append(f"JAVA_TOOL_OPTIONS={options}\n{java.TRUST_MANIFEST_ENV}={manifest_path}\n",
                      [*protected, store, manifest_path])
        # Export must not be able to alias or alter the source, vendor policy,
        # or qualified copy after their earlier hashes passed.
        if (java.file_digest(source) != source_digest or java.file_digest(store) != copy_digest
                or java.vendor_security(home) != security
                or java.artifact_parent(temporary_root, directory) != parent_identity):
            raise ValueError("Java artifacts changed during the final environment export")
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
