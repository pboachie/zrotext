"""Stage deterministic, licensed source archives of the reviewed generated files.

These are experimental source bundles, not registry packages or release approval.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "sdk/tungsten"


def reviewed_files(directory, inventory):
    directory = directory.resolve()
    grouped = {}
    for name, digest in sorted(inventory.items()):
        parts = PurePosixPath(name).parts
        if len(parts) < 2 or any(p in ("..", ".") for p in parts) or "\\" in name:
            raise ValueError("Invalid source inventory path")
        file = (directory / name).resolve()
        if not file.is_relative_to(directory):
            raise ValueError("Source inventory escapes generated output")
        contents = file.read_bytes()
        if hashlib.sha256(contents).hexdigest() != digest:
            raise ValueError("Generated file differs from reviewed lock: " + name)
        grouped.setdefault(parts[0], {})["/".join(parts[1:])] = contents
    if not grouped:
        raise ValueError("Empty source inventory")
    return grouped


def source_archive(files):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True,
                        help="external artifact directory, outside the repository")
    args = parser.parse_args()
    destination = args.out.resolve()
    if destination.is_relative_to(ROOT.resolve()):
        raise ValueError("Put package artifacts outside the public working tree")
    inventory = json.loads((CONFIG / "generated.lock.json").read_text())
    grouped = reviewed_files(CONFIG / "generated", inventory)
    license_bytes = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    destination.mkdir(parents=True, exist_ok=True)
    checksums = []
    for target, files in sorted(grouped.items()):
        files["LICENSE"] = license_bytes
        payload = source_archive(files)
        name = "zrotext-" + target + "-experimental-source.tar.gz"
        (destination / name).write_bytes(payload)
        checksums.append(hashlib.sha256(payload).hexdigest() + "  " + name)
    (destination / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8", newline="\n")
    print("Wrote", len(grouped), "licensed source bundles; no registry publication or runtime parity implied")


if __name__ == "__main__":
    main()
