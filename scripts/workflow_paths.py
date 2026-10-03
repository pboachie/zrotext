# SPDX-License-Identifier: AGPL-3.0-only
"""Independently selected filesystem capabilities for guided setup."""
import os
from pathlib import Path
import stat


def refused():
    raise ValueError("guided_path_refused")


def identity(path):
    info = os.stat(path, follow_symlinks=False)
    return info.st_dev, info.st_ino


def artifact_capability(value=None):
    # This root is selected independently by setup or its reviewed launcher.
    raw = os.fspath(value if value is not None else os.getcwd())
    if not os.path.isabs(raw) or raw.startswith(("\\\\", "//")) or any(ord(c) < 32 for c in raw):
        raise ValueError("guided_path_refused")
    root = os.path.normcase(os.path.abspath(raw))
    if os.path.dirname(root) == root:
        raise ValueError("guided_path_refused")
    canonical = os.path.normcase(os.path.realpath(root))
    if canonical != root:
        raise ValueError("guided_path_refused")
    current = Path(root)
    while current != current.parent:
        info = os.lstat(current)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("guided_path_refused")
        if os.name == "posix":
            if current == Path(root) and (info.st_uid != os.getuid() or info.st_mode & 0o022):
                raise ValueError("guided_path_refused")
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise ValueError("guided_path_refused")
        current = current.parent
    return root


def setup_artifact_root(broker):
    installed = os.path.normcase(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    normalized = os.path.normcase(os.path.abspath(os.fspath(broker)))
    # Both alternatives are independent capabilities, not candidate parents.
    return artifact_capability(installed if normalized.startswith(installed + os.path.sep) else os.getcwd())


def checked_path(candidate, *, artifact=False, approved_artifact_root=None):
    raw = os.fspath(candidate)
    if not os.path.isabs(raw) or raw.startswith(("\\\\", "//")) or any(ord(c) < 32 for c in raw):
        raise ValueError("guided_path_refused")
    normalized = os.path.normcase(os.path.abspath(raw))
    # CWD is a deliberate launcher capability; never infer it from candidate.
    roots = [os.path.normcase(os.path.abspath(os.getcwd())), os.path.normcase(os.path.abspath(os.path.join(os.path.expanduser("~"), ".config")))]
    if artifact:
        roots.append(os.path.normcase(os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))))
        if approved_artifact_root is not None:
            roots = [artifact_capability(approved_artifact_root)]
    selected = None
    for root in roots:
        if root == os.path.abspath(os.path.sep) or os.path.dirname(root) == root:
            continue
        if normalized.startswith(root + os.path.sep):
            selected = root
            break
    if selected is None:
        raise ValueError("guided_path_refused")
    # Dominating normalized containment precedes all candidate filesystem reads.
    if not normalized.startswith(selected + os.path.sep):
        raise ValueError("guided_path_refused")
    canonical_root = os.path.normcase(os.path.realpath(selected))
    canonical = os.path.normcase(os.path.realpath(normalized))
    if not canonical.startswith(canonical_root + os.path.sep) or os.path.normcase(canonical) != os.path.normcase(normalized):
        raise ValueError("guided_path_refused")
    current = Path(normalized)
    anchor_info = os.lstat(selected)
    if (not stat.S_ISDIR(anchor_info.st_mode) or stat.S_ISLNK(anchor_info.st_mode)
            or getattr(anchor_info, "st_file_attributes", 0) & 0x400
            or (not artifact and os.name == "posix" and (anchor_info.st_uid != os.getuid() or anchor_info.st_mode & 0o022))):
        raise ValueError("guided_path_refused")
    while current != Path(selected):
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if current != Path(normalized):
                raise ValueError("guided_path_refused") from None
        else:
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("guided_path_refused")
            if current == Path(normalized) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise ValueError("guided_path_refused")
            if not artifact and os.name == "posix" and info.st_uid != os.getuid():
                raise ValueError("guided_path_refused")
            if (not artifact and os.name == "posix" and current != Path(normalized)
                    and (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022)):
                raise ValueError("guided_path_refused")
        current = current.parent
    return Path(normalized)


class ParentGuard:
    def __init__(self, path):
        self.path = checked_path(path)
        self.parent_identity = identity(self.path.parent)
        self.file_identity = identity(self.path) if self.path.exists() else None

    def check(self, *, parent_only=False):
        checked_path(self.path)
        if identity(self.path.parent) != self.parent_identity:
            raise ValueError("guided_path_refused")
        if parent_only:
            return
        actual = identity(self.path) if self.path.exists() else None
        if actual != self.file_identity:
            raise ValueError("configuration_changed")
