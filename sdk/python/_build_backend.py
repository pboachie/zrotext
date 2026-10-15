"""Small offline PEP 517 backend with an explicit public artifact allowlist."""

import base64
import csv
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
MODULES = ("__init__.py", "alpha.py", "webhook.py")
LIMIT = 1024 * 1024


def read_regular(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            raise ValueError("linked artifact input refused")
    if not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("missing or oversized artifact input")
    return path.read_bytes()


def identity():
    project = tomllib.loads(read_regular(ROOT / "pyproject.toml").decode())["project"]
    if project["name"] != "zrotext-client" or project["version"] != "0.1.7rc1":
        raise ValueError("unreviewed package identity")
    if project["dependencies"] or project["license"] != "AGPL-3.0-only":
        raise ValueError("unreviewed dependencies or license")
    if project["requires-python"] != ">=3.11":
        raise ValueError("unreviewed runtime")
    return "zrotext_client-" + project["version"], project


def license_bytes():
    local = ROOT / "LICENSE"
    return read_regular(local if local.exists() else ROOT.parent.parent / "LICENSE")


def metadata():
    _, project = identity()
    lines = ["Metadata-Version: 2.4", "Name: " + project["name"],
             "Version: " + project["version"], "Summary: " + project["description"],
             "Requires-Python: " + project["requires-python"],
             "License-Expression: AGPL-3.0-only", "License-File: LICENSE",
             "Project-URL: Repository, " + project["urls"]["Repository"],
             "Description-Content-Type: text/markdown", "", ""]
    return "\n".join(lines).encode() + read_regular(ROOT / "README.md")


def wheel_files():
    stem, _ = identity()
    dist = stem + ".dist-info"
    files = {"zrotext_client/" + name: read_regular(ROOT / "zrotext_client" / name)
             for name in MODULES}
    files[dist + "/METADATA"] = metadata()
    files[dist + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: zrotext-offline\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[dist + "/licenses/LICENSE"] = license_bytes()
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(data))])
    writer.writerow([dist + "/RECORD", "", ""])
    files[dist + "/RECORD"] = record.getvalue().encode()
    return files


def sdist_files():
    files = {name: read_regular(ROOT / name)
             for name in ("pyproject.toml", "_build_backend.py", "README.md")}
    files.update({"zrotext_client/" + name: read_regular(ROOT / "zrotext_client" / name)
                  for name in MODULES})
    files["LICENSE"] = license_bytes()
    files["PKG-INFO"] = metadata()
    return files


def _settings(config_settings):
    if config_settings:
        raise ValueError("custom build settings unsupported")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _settings(config_settings)
    stem, _ = identity()
    filename = stem + "-py3-none-any.whl"
    with zipfile.ZipFile(Path(wheel_directory) / filename, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(wheel_files().items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return filename


def build_sdist(sdist_directory, config_settings=None):
    _settings(config_settings)
    stem, _ = identity()
    filename = stem + ".tar.gz"
    with (Path(sdist_directory) / filename).open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in sorted(sdist_files().items()):
                    entry = tarfile.TarInfo(stem + "/" + name)
                    entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                    archive.addfile(entry, io.BytesIO(data))
    return filename
