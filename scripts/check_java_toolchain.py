# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only qualification of the selected CI JDK and its default or qualified job-local JSSE trust store."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


MINIMUM_VERSIONS = {17: (17, 0, 21, 0, 9), 21: (21, 0, 13, 0, 9)}
DISTRIBUTIONS = {"temurin": ("Eclipse Adoptium", 9), "corretto": ("Amazon.com Inc.", 10)}
TRUST_MANIFEST_ENV = "CI_JAVA_TRUST_MANIFEST"
TRUST_DIRECTORY_PREFIX = "ci-java-tls-"
# G3/AAA parent scope: https://ops.java/emudhra and its linked CheckCerts.java.
# CVE-2026-114820 additionally requires removing G1/G2:
# https://www.oracle.com/java/technologies/javase/21-0-13-0-3-relnotes.html
# Certificate SHA-256 (not SPKI), from the CCADB Microsoft Included CA report:
# https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFT
IMPACTED_ROOTS = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b":
        ("emSign ECC Root CA - G3", "CVE-2026-91403 / CVE-2026-114820"),
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4":
        ("AAA Certificate Services", "CVE-2026-91403 / CVE-2026-114820"),
    "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367":
        ("emSign Root CA - G1", "CVE-2026-114820"),
    "1aa0c2709e831bd6e3b5129a00ba41f7eeef020872f1e6504bf0f6c3f24f3af3":
        ("emSign Root CA - G2", "CVE-2026-114820"),
}


def java_properties(output):
    properties = {}
    for line in output.splitlines():
        match = re.fullmatch(r"\s+([\w.]+) = (.*)", line)
        if match:
            key, value = match.groups()
            if key in properties:
                raise ValueError("Duplicate Java property; runtime is unverified")
            properties[key] = value
    return properties


def verify_runtime(properties, major, expected_trust=None, distribution="temurin"):
    version = properties.get("java.runtime.version", "")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\+(\d+)(?:-LTS)?", version)
    if not match:
        raise ValueError("Unrecognized Java runtime version; runtime is unverified")
    parsed = tuple(int(value or 0) for value in match.groups())
    vendor, build = DISTRIBUTIONS[distribution]
    floor = (*MINIMUM_VERSIONS[major][:-1], build)
    if parsed[0] != major or parsed < floor:
        raise ValueError("Java runtime is below the required same-major CI patch floor")
    if properties.get("java.vendor") != vendor:
        raise ValueError("Java vendor does not match the qualified distribution")
    trust = {key: value for key, value in properties.items() if key.startswith("javax.net.ssl.trustStore")}
    if trust != (expected_trust or {}):
        raise ValueError("Custom JSSE trust configuration is unverified by this CI gate")
    if "java.security.properties" in properties:
        raise ValueError("Custom Java security policy is unverified by this CI gate")
    return version


def root_fingerprints(output):
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    encoded = re.findall(re.escape(begin) + r"\s*([A-Za-z0-9+/=\s]+?)\s*" + re.escape(end), output)
    if not encoded or output.count(begin) != len(encoded) or output.count(end) != len(encoded):
        raise ValueError("Default Java trust store is empty or unreadable; trust is unverified")
    fingerprints = set()
    for certificate in encoded:
        try:
            der = base64.b64decode("".join(certificate.split()), validate=True)
        except ValueError as error:
            raise ValueError("Malformed certificate listing; trust is unverified") from error
        if not der:
            raise ValueError("Empty certificate listing; trust is unverified")
        fingerprints.add(hashlib.sha256(der).hexdigest())
    return fingerprints


def verify_roots(fingerprints):
    if len(IMPACTED_ROOTS) != 4:
        raise ValueError("Impacted-root policy is incomplete; trust is unverified")
    if not fingerprints:
        raise ValueError("Empty root set; trust is unverified")
    found = set(IMPACTED_ROOTS) & fingerprints
    if found:
        names = ", ".join(sorted(f"{IMPACTED_ROOTS[value][0]} ({IMPACTED_ROOTS[value][1]})" for value in found))
        raise ValueError("Default Java trust store retains impacted root: " + names)


def read_tool(*command):
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        # Do not echo properties, environment, paths, or complete certificate listings.
        raise ValueError("Java inspection command did not complete; toolchain is unverified") from error
    return result.stdout + "\n" + result.stderr


def selected_runtime(major, expected_trust=None, distribution="temurin"):
    selected_home = os.environ.get("JAVA_HOME")
    if not selected_home:
        raise ValueError("JAVA_HOME must identify the selected CI JDK")
    home = Path(selected_home).resolve()
    suffix = ".exe" if os.name == "nt" else ""
    java = home / "bin" / ("java" + suffix)
    keytool = home / "bin" / ("keytool" + suffix)
    path_java = shutil.which("java")
    if not path_java or Path(path_java).resolve() != java.resolve():
        raise ValueError("PATH Java differs from JAVA_HOME; toolchain is unverified")
    properties = java_properties(read_tool(str(java), "-XshowSettings:properties", "-version"))
    version = verify_runtime(properties, major, expected_trust, distribution)
    if not properties.get("java.home") or Path(properties["java.home"]).resolve() != home:
        raise ValueError("Reported Java home differs from JAVA_HOME; toolchain is unverified")
    security = home / "lib" / "security"
    if (security / "jssecacerts").exists():
        raise ValueError("Custom jssecacerts trust store is unverified by this CI gate")
    return home, java, keytool, version


def vendor_store_password():
    # Public vendor cacerts integrity default, not an application/user secret.
    # Keep integrity verification enabled; custom stores/passwords are not accepted.
    return "changeit"


def probe(java, operation, *args, env=None):
    source = Path(__file__).with_name("JavaTrustProbe.java")
    parameters = [operation, *([vendor_store_password()] if operation in {"inventory", "filter"} else []),
                  *map(str, args)]
    try:
        result = subprocess.run([str(java), "--source", "17", str(source), *parameters],
                                check=True, capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Java trust probe did not complete; trust is unverified") from error
    return result.stdout


def decode_field(value):
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError("Malformed Java trust probe response") from error


def inventory(output):
    store_type, certificates = None, {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and fields[0] == "TYPE" and store_type is None:
            store_type = fields[1]
        elif len(fields) == 3 and fields[0] == "CERT" and re.fullmatch(r"[0-9a-f]{64}", fields[2]):
            alias = decode_field(fields[1])
            if not alias or alias in certificates:
                raise ValueError("Duplicate or empty certificate alias")
            certificates[alias] = {"sha256": fields[2], "entry_type": "trusted-certificate", "attributes": {}}
        elif len(fields) == 4 and fields[0] == "ATTRIBUTE":
            alias, name, value = map(decode_field, fields[1:])
            if alias not in certificates or not name or name in certificates[alias]["attributes"]:
                raise ValueError("Unknown entry or duplicate/empty certificate attribute")
            certificates[alias]["attributes"][name] = value
        else:
            raise ValueError("Unexpected Java trust inventory response")
    if store_type not in {"JKS", "PKCS12"} or not certificates:
        raise ValueError("Unsupported or empty Java trust inventory")
    return store_type, certificates


def fingerprints(certificates):
    return {certificate["sha256"] for certificate in certificates.values()}


def retained_certificates(certificates):
    return {alias: certificate for alias, certificate in certificates.items()
            if certificate["sha256"] not in IMPACTED_ROOTS}


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def validate_local_metadata(metadata, *, directory=False, private=False):
    """Check job-owned artifacts, not vendor installations or global stores.

    Windows does not expose POSIX ownership/ACL semantics through stat. Its
    runner-provisioned ACL remains a trust boundary; reject reparse points on
    both platforms and do not pretend chmod bits validate a Windows ACL.
    """
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError("Job artifact must be an ordinary file or directory without reparse points")
    if not directory and metadata.st_nlink != 1:
        raise ValueError("Job artifact must not have hard-link aliases")
    if os.name == "posix":
        forbidden = 0o077 if private and directory else 0o022
        if metadata.st_uid != os.geteuid() or metadata.st_mode & forbidden:
            raise ValueError("Job artifact ownership or permissions are unqualified")


def ordinary_directory(path, *, private=False):
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("Job directory must be absolute and must not traverse links")
    metadata = path.lstat()
    validate_local_metadata(metadata, directory=True, private=private)
    return file_identity(metadata)


def runner_temporary_root():
    try:
        root = Path(os.environ["RUNNER_TEMP"])
        ordinary_directory(root)
        return root
    except (KeyError, OSError, RuntimeError) as error:
        raise ValueError("An ordinary runner-owned temporary directory is required") from error


def artifact_parent(root, directory):
    if directory.parent != root or not directory.name.startswith(TRUST_DIRECTORY_PREFIX):
        raise ValueError("Trust artifact is outside its per-job directory")
    ordinary_directory(root)
    return ordinary_directory(directory, private=True)


def open_local_file(path, flags):
    """Bind an existing ordinary file to a descriptor; never create a target.

    O_NOFOLLOW/O_NONBLOCK strengthen POSIX opens. On Windows, lstat reparse
    checks and before/opened/after file identities catch path replacement;
    these checks are not a sandbox against a malicious same-user process.
    """
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("Job file must be absolute and must not traverse links")
    before = path.lstat()
    validate_local_metadata(before)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        validate_local_metadata(opened)
        validate_local_metadata(after)
        if file_identity(before) != file_identity(opened) or file_identity(after) != file_identity(opened):
            raise ValueError("Job file identity changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def vendor_security(home):
    # Preserve the vendor algorithm policy and compromised-certificate blocklist.
    return {name: file_digest(home / name) for name in
            ("conf/security/java.security", "lib/security/blocked.certs")}


def trust_properties(store, store_type):
    return {"javax.net.ssl.trustStore": str(store), "javax.net.ssl.trustStoreType": store_type,
            "javax.net.ssl.trustStorePassword": vendor_store_password()}


def verify_effective(output, store, certificates):
    selected, roots = None, set()
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2 and fields[0] == "SELECTED" and selected is None:
            selected = decode_field(fields[1])
        elif len(fields) == 2 and fields[0] == "ROOT" and re.fullmatch(r"[0-9a-f]{64}", fields[1]):
            if fields[1] in roots:
                raise ValueError("Duplicate effective trust root")
            roots.add(fields[1])
        else:
            raise ValueError("Unexpected effective TrustManager response")
    if selected != str(store) or roots != fingerprints(certificates):
        raise ValueError("Effective JSSE TrustManager differs from the qualified job-local copy")
    verify_roots(roots)


def load_manifest():
    try:
        manifest_path = Path(os.environ[TRUST_MANIFEST_ENV])
        temporary_root = runner_temporary_root()
        parent_identity = artifact_parent(temporary_root, manifest_path.parent)
        if manifest_path.name != "trust.json":
            raise ValueError("Trust manifest is not an ordinary per-job artifact")
        descriptor = open_local_file(manifest_path, os.O_RDONLY)
        try:
            before = os.fstat(descriptor)
            if before.st_size > 1_000_000:
                raise ValueError("Trust manifest is too large")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                data = source.read(1_000_001)
            after = os.fstat(descriptor)
            if (len(data) > 1_000_000 or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or file_identity(manifest_path.lstat()) != file_identity(before)):
                raise ValueError("Trust manifest changed while reading")
            manifest = json.loads(data.decode("utf-8"))
        finally:
            os.close(descriptor)
        if (set(manifest) != {"schema", "java_home", "source_sha256", "copy_sha256", "store_type",
                              "source_inventory", "copy_inventory", "vendor_security"} or manifest["schema"] != 2
                or manifest["store_type"] not in {"JKS", "PKCS12"}):
            raise ValueError("Unexpected trust manifest schema")
        store = manifest_path.parent / "cacerts"
        descriptor = open_local_file(store, os.O_RDONLY)
        os.close(descriptor)
        if artifact_parent(temporary_root, manifest_path.parent) != parent_identity:
            raise ValueError("Trust artifact directory changed during inspection")
        return manifest, store
    except (KeyError, OSError, TypeError, UnicodeError, RuntimeError, json.JSONDecodeError) as error:
        raise ValueError("Job-local trust manifest is unavailable or malformed") from error


def verify_copy(java, home, store, manifest):
    source = home / "lib/security/cacerts"
    if (str(home) != manifest["java_home"] or file_digest(source) != manifest["source_sha256"]
            or file_digest(store) != manifest["copy_sha256"]
            or vendor_security(home) != manifest["vendor_security"]):
        raise ValueError("The original store or qualified copy changed")
    source_type, original = inventory(probe(java, "inventory", source))
    copy_type, copied = inventory(probe(java, "inventory", store))
    expected = retained_certificates(original)
    if (source_type != copy_type or copy_type != manifest["store_type"] or copied != expected
            or original != manifest["source_inventory"] or copied != manifest["copy_inventory"]):
        raise ValueError("A non-target alias, certificate, entry type or attribute changed")
    verify_roots(fingerprints(copied))
    verify_effective(probe(java, "effective"), store, copied)
    if (file_digest(source) != manifest["source_sha256"]
            or file_digest(store) != manifest["copy_sha256"]
            or vendor_security(home) != manifest["vendor_security"]):
        raise ValueError("The trust stores or vendor security policy changed during verification")


def check(major, distribution="temurin"):
    if TRUST_MANIFEST_ENV in os.environ:
        manifest, store = load_manifest()
        home, java, _, version = selected_runtime(major, trust_properties(store, manifest["store_type"]), distribution)
        verify_copy(java, home, store, manifest)
        print(f"{distribution} {version}: CI patch floor and effective job-local JSSE trust checks passed")
        return
    home, _, keytool, version = selected_runtime(major, distribution=distribution)
    security = home / "lib" / "security"
    listing = read_tool(str(keytool), "-list", "-rfc", "-keystore", str(security / "cacerts"),
                        "-storepass", vendor_store_password())
    verify_roots(root_fingerprints(listing))
    print(f"{distribution} {version}: CI patch floor and default impacted-root checks passed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=sorted(MINIMUM_VERSIONS), required=True)
    parser.add_argument("--distribution", choices=sorted(DISTRIBUTIONS), default="temurin")
    args = parser.parse_args(argv)
    try:
        check(args.major, args.distribution)
    except (ValueError, OSError) as error:
        print(str(error) if isinstance(error, ValueError) else "Java trust inspection could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
