# SPDX-License-Identifier: AGPL-3.0-only
"""Add the locked native build graph and all packaged libraries to CycloneDX.

Cargo's normal/build graph includes build dependencies and proc macros. It is
an intentionally conservative source inventory, not binary composition proof.
Only package identities, never Cargo's private local paths, enter the SBOM.
The reviewed HPKE bridge binds its vendored wolfSSL provenance and five source
inputs. Graphics libraries map only through a hash-verified resolved Maven AAR.
This source inventory and exact artifact mapping do not prove runtime behavior
or which individual vendored files the linker retained. Existing version-one
inventories intentionally fail the complete-library gate and must be rebuilt.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
import zipfile

ABIS = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "x86": "i686-linux-android",
}
ROOT_PACKAGE = "zrotext-android-owner-custody"
ROOT_MATERIAL = "zrotext-root-material"
LIBRARY = "libzrotext_android_owner_custody.so"
HPKE_LIBRARY = "libzrotext_hpke_keystore.so"
GRAPHICS_LIBRARY = "libandroidx.graphics.path.so"
LIBRARIES = (LIBRARY, HPKE_LIBRARY, GRAPHICS_LIBRARY)
WOLF_VERSION = "5.9.4"
WOLF_COMMIT = "3c5eead44904df64e6a5a1f4ebdce377d35a849a"
WOLF_REF = f"pkg:generic/wolfssl@{WOLF_VERSION}?commit={WOLF_COMMIT}"
BRIDGE_FILES = ("CMakeLists.txt", "user_settings.h", "zrotext_hpke_core.c",
                "zrotext_hpke_core.h", "zrotext_hpke_jni.c")
PROPERTY = "zrotext:native-build-inventory"
SCOPE = "locked normal/build dependency graph, including build dependencies and proc macros"
PACKAGED_SCOPE = "exact packaged shared-library hashes with conservative reviewed source inventories; not binary composition or runtime proof"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
HEX = re.compile(r"[0-9a-f]{64}\Z")
LINE = re.compile(r"(\d+)([A-Za-z0-9_-]+) v([A-Za-z0-9_.+-]+)([^|]*)\|([^|]*)\|([^|]*)\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_file(path):
    # Git's clean-content check does not establish directory incarnations.
    # Reject linked ancestors before opening a vendor or first-party input.
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
           for p in (path, *path.parents)) \
            or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Native source input is missing, linked or oversized")
    return path.read_bytes()


def collect_vendor(repo):
    """Verify every vendored file, without claiming every file is linked."""
    cpp = repo / "android/app/src/main/cpp"
    vendor = cpp / "wolfssl"
    raw = source_file(vendor / "PROVENANCE")
    text = raw.decode("utf-8")
    header, records = text.split("\n\n", 1)
    if header != ("Vendored wolfSSL subset for the ZROtext AndroidKeyStore HPKE bridge.\n"
                  f"Upstream: https://github.com/wolfSSL/wolfssl tag v{WOLF_VERSION}-stable\n"
                  f"Commit: {WOLF_COMMIT}\n"
                  "License: GPLv3-or-later (see LICENSING); unmodified copies."):
        raise ValueError("Vendored wolfSSL provenance identity differs")
    files = {}
    for line in records.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            raise ValueError("Vendored wolfSSL provenance record is malformed")
        expected, name = match.groups()
        if any(part in ("", ".", "..") for part in name.split("/")) or name in files:
            raise ValueError("Vendored wolfSSL provenance path is unsafe or duplicated")
        path = vendor / name
        if not path.resolve().is_relative_to(vendor.resolve()) or digest(source_file(path)) != expected:
            raise ValueError("Vendored wolfSSL source differs from provenance")
        files[name] = expected
    actual = set()
    for path in vendor.rglob("*"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("Vendored wolfSSL contains a linked path")
        if path.is_file() and path != vendor / "PROVENANCE":
            actual.add(path.relative_to(vendor).as_posix())
    if len(files) != 232 or actual != set(files) or "LICENSING" not in files \
            or f'#define LIBWOLFSSL_VERSION_STRING "{WOLF_VERSION}"' not in source_file(vendor / "wolfssl/version.h").decode("utf-8"):
        raise ValueError("Vendored wolfSSL inventory or version differs")
    return {
        "vendor": {"version": WOLF_VERSION, "upstream_commit": WOLF_COMMIT,
                   "license": "GPL-3.0-or-later", "provenance_sha256": digest(raw),
                   "files_sha256": digest(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()),
                   "file_count": len(files)},
        "bridge_sources": {name: digest(source_file(cpp / name)) for name in BRIDGE_FILES},
    }


def graphics_component(bom, facts=None):
    matches = [c for c in bom["components"]
               if re.fullmatch(r"pkg:maven/androidx\.graphics/graphics-path@[0-9]+\.[0-9]+\.[0-9]+\?type=aar", c.get("purl", ""))]
    if len(matches) != 1:
        raise ValueError("Native graphics inventory requires one resolved Maven AAR")
    component = matches[0]
    hashes = [h.get("content") for h in component.get("hashes", []) if h.get("alg") == "SHA-256"]
    version = component["purl"].split("@", 1)[1].split("?", 1)[0]
    if component.get("bom-ref") != component["purl"] or component.get("version") != version \
            or len(hashes) != 1 or not isinstance(hashes[0], str) or not HEX.fullmatch(hashes[0]) \
            or {"license": {"id": "Apache-2.0"}} not in component.get("licenses", []):
        raise ValueError("Native graphics Maven identity, digest or license differs")
    if facts is not None and (facts["ref"] != component["purl"] or facts["version"] != version
                              or facts["aar_sha256"] != hashes[0]):
        raise ValueError("Native graphics mapping differs from the Maven inventory")
    return component, version, hashes[0]


def graphics_entries(raw):
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if len(infos) > 4096 or len({i.filename for i in infos}) != len(infos):
            raise ValueError("Native graphics archive entries are excessive or duplicated")
        expected = {f"jni/{abi}/{GRAPHICS_LIBRARY}" for abi in ABIS}
        native = [i for i in infos if i.filename.endswith(".so")]
        if {i.filename for i in native} != expected or any(i.file_size > 16 * 1024 * 1024 for i in native):
            raise ValueError("Native graphics archive libraries differ")
        return {i.filename.replace("jni/", "lib/", 1): digest(archive.read(i)) for i in native}


def collect_packaged_sources(bom, entries, repo, environment):
    facts = collect_vendor(repo)
    component, version, expected = graphics_component(bom)
    cache = Path(environment.get("GRADLE_USER_HOME", str(Path.home() / ".gradle")))
    directory = cache / "caches/modules-2/files-2.1/androidx.graphics/graphics-path" / version
    candidates = list(directory.glob(f"*/graphics-path-{version}.aar"))
    if not candidates or len(candidates) > 16:
        raise ValueError("Resolved native graphics AAR is missing or ambiguous")
    matches = []
    for path in candidates:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Resolved native graphics AAR is linked or oversized")
        raw = path.read_bytes()
        if digest(raw) == expected:
            matches.append(raw)
    if not matches:
        raise ValueError("Resolved native graphics AAR digest differs")
    native = graphics_entries(matches[0])
    if any(entries.get(name) != value for name, value in native.items()):
        raise ValueError("Packaged graphics bytes differ from the resolved Maven AAR")
    facts["graphics"] = {"ref": component["purl"], "version": version,
                         "aar_sha256": expected, "entries": native}
    return facts


def packaged_components(facts, entries, commit):
    """Closed identities and exact source facts for this reviewed native build."""
    if set(facts) != {"vendor", "bridge_sources", "graphics"}:
        raise ValueError("Packaged native source inventory is malformed")
    vendor, bridge, graphics = facts["vendor"], facts["bridge_sources"], facts["graphics"]
    if set(vendor) != {"version", "upstream_commit", "license", "provenance_sha256", "files_sha256", "file_count"} \
            or vendor["version"] != WOLF_VERSION or vendor["upstream_commit"] != WOLF_COMMIT \
            or vendor["license"] != "GPL-3.0-or-later" or type(vendor["file_count"]) is not int or vendor["file_count"] != 232 \
            or any(not isinstance(vendor[name], str) or not HEX.fullmatch(vendor[name]) for name in ("provenance_sha256", "files_sha256")) \
            or set(bridge) != set(BRIDGE_FILES) or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in bridge.values()) \
            or set(graphics) != {"ref", "version", "aar_sha256", "entries"} \
            or not isinstance(graphics["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", graphics["version"]) \
            or graphics["ref"] != f'pkg:maven/androidx.graphics/graphics-path@{graphics["version"]}?type=aar' \
            or not isinstance(graphics["aar_sha256"], str) or not HEX.fullmatch(graphics["aar_sha256"]) \
            or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Packaged native source identity differs")
    expected = {f"lib/{abi}/{library}" for abi in ABIS for library in LIBRARIES}
    if {name for name in entries if name.endswith(".so") or name.startswith("lib/")} != expected \
            or any(not isinstance(entries[name], str) or not HEX.fullmatch(entries[name]) for name in expected):
        raise ValueError("APK must contain exactly twelve reviewed native libraries")
    if set(graphics["entries"]) != {f"lib/{abi}/{GRAPHICS_LIBRARY}" for abi in ABIS} \
            or any(entries[name] != value for name, value in graphics["entries"].items()):
        raise ValueError("Packaged graphics mapping differs from the resolved AAR")
    bridge_ref = f"pkg:generic/zrotext-hpke-keystore@{commit}"
    nodes = [{"type": "library", "name": "wolfssl", "version": WOLF_VERSION,
              "purl": WOLF_REF, "bom-ref": WOLF_REF,
              "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
              "properties": [{"name": "zrotext:vendored-source", "value": json.dumps(vendor, sort_keys=True, separators=(",", ":"))}],
              "externalReferences": [{"type": "vcs", "url": f"https://github.com/wolfSSL/wolfssl/tree/{WOLF_COMMIT}"}]},
             {"type": "library", "name": "zrotext-hpke-keystore", "version": commit,
              "purl": bridge_ref, "bom-ref": bridge_ref,
              "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
              "properties": [{"name": "zrotext:workspace-source-commit", "value": commit},
                             {"name": "zrotext:bridge-sources", "value": json.dumps(bridge, sort_keys=True, separators=(",", ":"))}]}]
    edges = {WOLF_REF: set(), bridge_ref: {WOLF_REF}}
    for abi in ABIS:
        for library, name, version, parent in [(HPKE_LIBRARY, "zrotext-hpke-keystore", commit, bridge_ref),
                                               (GRAPHICS_LIBRARY, "androidx-graphics-path", graphics["version"], graphics["ref"])]:
            identity = f"pkg:generic/{name}@{version}?arch={abi}"
            entry = f"lib/{abi}/{library}"
            nodes.append({"type": "library", "name": name, "version": version,
                          "purl": identity, "bom-ref": identity,
                          "hashes": [{"alg": "SHA-256", "content": entries[entry]}],
                          "properties": [{"name": "zrotext:apk-entry", "value": entry}]})
            edges[identity] = {parent}
    return nodes, edges


def is_packaged_component(component):
    """Permit only the finite native identity families, never arbitrary generic packages."""
    identity = component.get("purl", "")
    return component.get("bom-ref") == identity and (identity == WOLF_REF or bool(re.fullmatch(
        r"pkg:generic/(?:zrotext-hpke-keystore@[0-9a-f]{40}(?:\?arch=(?:arm64-v8a|armeabi-v7a|x86_64|x86))?|"
        r"androidx-graphics-path@[0-9]+\.[0-9]+\.[0-9]+\?arch=(?:arm64-v8a|armeabi-v7a|x86_64|x86))", identity)))


def ref(name, version):
    return f"pkg:cargo/{name}@{version}"


def tree_graph(text, locked, repo):
    """Read Cargo's depth format; preserve every parent edge on deduped visits."""
    graph, facts, stack = {}, {}, []
    for line in text.splitlines():
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError("Native Cargo tree has an unrecognized package record")
        depth, name, version, suffix, license_text, features = match.groups()
        depth = int(depth)
        identity = ref(name, version)
        if depth > len(stack) or (depth == 0 and stack):
            raise ValueError("Native Cargo tree has an invalid depth")
        lock = locked.get((name, version))
        if lock is None:
            raise ValueError("Native Cargo package is absent or ambiguous in Cargo.lock")
        repeat = features.endswith(" (*)")
        features = features.removesuffix(" (*)")
        suffix = suffix.replace(" (proc-macro)", "").strip()
        if lock.get("source"):
            if lock["source"] != REGISTRY or suffix or not HEX.fullmatch(lock.get("checksum", "")):
                raise ValueError("Native registry package has unsupported source or checksum")
        else:
            if not (suffix.startswith("(") and suffix.endswith(")")):
                raise ValueError("Native workspace package has no source path")
            if not Path(suffix[1:-1]).resolve().is_relative_to(repo.resolve()):
                raise ValueError("Native path dependency is outside the reviewed source")
        if repeat and identity not in facts:
            raise ValueError("Native Cargo tree repeats a package before its definition")
        if identity in facts and facts[identity] != (lock, license_text, features):
            raise ValueError("Native Cargo tree has inconsistent package facts")
        facts[identity] = (lock, license_text, features)
        graph.setdefault(identity, set())
        if depth:
            graph[stack[depth - 1]].add(identity)
        stack[depth:] = [identity]
    if not stack or not next(iter(facts)).startswith(f"pkg:cargo/{ROOT_PACKAGE}@"):
        raise ValueError("Native Cargo tree has the wrong root")
    return graph, facts


def merge_inventory(bom, lock_bytes, trees, entries, commit, repo, *, packaged):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or set(trees) != set(ABIS):
        raise ValueError("Native inventory requires the exact source and four targets")
    packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    locked = {}
    for package in packages:
        key = (package["name"], package["version"])
        # Cargo.lock may contain multiple registries with one name/version.
        locked[key] = package if key not in locked else None
    result = copy.deepcopy(bom)
    components = result["components"]
    dependencies = result.setdefault("dependencies", [])
    native, edges, root = {}, {}, None
    for abi, text in trees.items():
        graph, facts = tree_graph(text, locked, repo)
        this_root = next(iter(facts))
        if root is not None and root != this_root:
            raise ValueError("Native ABI graphs have different root packages")
        root = this_root
        for identity, (package, license_text, features) in facts.items():
            component = native.setdefault(identity, {
                "type": "library", "name": package["name"], "version": package["version"],
                "purl": identity, "bom-ref": identity, "properties": [],
            })
            if package.get("source"):
                component["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
            else:
                if not any(prop["name"] == "zrotext:workspace-source-commit"
                           for prop in component["properties"]):
                    component["properties"].append({"name": "zrotext:workspace-source-commit", "value": commit})
            if license_text:
                component["licenses"] = [{"expression": license_text.replace("/", " OR ")}]
            component["properties"].append({"name": f"zrotext:cargo-features:{abi}", "value": features})
            edges.setdefault(identity, set()).update(graph[identity])
    components.extend(native[identity] for identity in sorted(native))
    for abi, target in ABIS.items():
        entry = f"lib/{abi}/{LIBRARY}"
        digest = entries.get(entry, "")
        if not HEX.fullmatch(digest):
            raise ValueError("Native inventory requires all four packaged library hashes")
        identity = root + f"?arch={abi}"
        components.append({
            "type": "library", "name": ROOT_PACKAGE, "version": native[root]["version"],
            "purl": identity, "bom-ref": identity,
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": [{"name": "zrotext:apk-entry", "value": entry},
                           {"name": "zrotext:rust-target", "value": target}],
        })
        edges[identity] = {root}
    dependencies.extend({"ref": identity, "dependsOn": sorted(edges[identity])}
                        for identity in sorted(edges))
    application = result["metadata"]["component"]
    application_ref = application.setdefault("bom-ref", "zrotext:android-application")
    application_edges = [edge for edge in dependencies if edge.get("ref") == application_ref]
    if len(application_edges) > 1:
        raise ValueError("SBOM application dependency record is duplicated")
    if not application_edges:
        application_edges = [{"ref": application_ref, "dependsOn": []}]
        dependencies.extend(application_edges)
    children = application_edges[0].setdefault("dependsOn", [])
    children.extend(root + f"?arch={abi}" for abi in ABIS)
    packaged_nodes, packaged_edges = packaged_components(packaged, entries, commit)
    components.extend(packaged_nodes)
    dependencies.extend({"ref": identity, "dependsOn": sorted(children)}
                        for identity, children in sorted(packaged_edges.items()))
    children.extend(identity for identity in packaged_edges if "?arch=" in identity)
    properties = result["metadata"].setdefault("properties", [])
    if any(prop.get("name") == PROPERTY for prop in properties):
        raise ValueError("SBOM already contains a native inventory")
    properties.append({"name": PROPERTY, "value": json.dumps({
        "version": 2, "source_commit": commit,
        "cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "root": root, "targets": ABIS, "scope": SCOPE,
        "packaged_scope": PACKAGED_SCOPE, "packaged": packaged,
    }, sort_keys=True, separators=(",", ":"))})
    verify_inventory(result, entries, commit)
    return result


def collect_inventory(bom, apk_entries, commit, repo, environment):
    packaged = collect_packaged_sources(bom, apk_entries, repo, environment)
    trees = {}
    for abi, target in ABIS.items():
        completed = subprocess.run([
            "cargo", "tree", "--locked", "--offline", "--package", ROOT_PACKAGE,
            "--target", target, "--edges", "normal,build", "--prefix", "depth",
            "--format", "{p}|{l}|{f}",
        ], cwd=repo, env=environment, capture_output=True, text=True,
            encoding="utf-8", timeout=180, check=False, shell=False)
        if completed.returncode:
            # Cargo errors may contain local paths or registry credentials.
            raise ValueError("Locked native Cargo inventory could not be resolved")
        trees[abi] = completed.stdout
    return merge_inventory(bom, (repo / "Cargo.lock").read_bytes(), trees,
                           apk_entries, commit, repo, packaged=packaged)


def properties(component):
    values = {}
    for prop in component.get("properties", []):
        if not isinstance(prop, dict) or set(prop) != {"name", "value"} \
                or not isinstance(prop["name"], str) or not isinstance(prop["value"], str) \
                or prop["name"] in values:
            raise ValueError("Native inventory properties are invalid or duplicated")
        values[prop["name"]] = prop["value"]
    return values


def verify_inventory(bom, entries, commit):
    """Verify source, graph shape and exact APK entry binding before signing."""
    try:
        manifest = json.loads(properties(bom["metadata"])[PROPERTY])
        if set(manifest) != {"version", "source_commit", "cargo_lock_sha256", "root", "targets", "scope", "packaged_scope", "packaged"} \
                or type(manifest["version"]) is not int or manifest["version"] != 2 or manifest["source_commit"] != commit \
                or manifest["targets"] != ABIS or manifest["scope"] != SCOPE \
                or manifest["packaged_scope"] != PACKAGED_SCOPE \
                or not HEX.fullmatch(manifest["cargo_lock_sha256"]):
            raise ValueError("Native inventory manifest differs from the reviewed source")
        root = manifest["root"]
        if not re.fullmatch(r"pkg:cargo/" + ROOT_PACKAGE + r"@[A-Za-z0-9_.+-]+", root):
            raise ValueError("Native inventory has the wrong root package")
        components = {}
        for component in bom["components"]:
            identity = component.get("bom-ref", component.get("purl"))
            if not isinstance(identity, str) or identity in components:
                raise ValueError("SBOM component references are missing or duplicated")
            components[identity] = component
        application = bom["metadata"]["component"]
        application_ref = application.get("bom-ref")
        if application_ref:
            if application_ref in components:
                raise ValueError("SBOM application reference duplicates a dependency")
            components[application_ref] = application
        graph = {}
        for dependency in bom.get("dependencies", []):
            identity = dependency["ref"]
            children = dependency.get("dependsOn", [])
            if identity not in components or identity in graph or not isinstance(children, list) \
                    or any(not isinstance(child, str) or child not in components for child in children) \
                    or len(set(children)) != len(children):
                raise ValueError("SBOM dependency references are invalid")
            graph[identity] = set(children)
        expected_entries = {f"lib/{abi}/{LIBRARY}" for abi in ABIS}
        actual_entries = {name for name in entries if name.endswith("/" + LIBRARY)}
        if actual_entries != expected_entries:
            raise ValueError("APK does not contain exactly four native owner libraries")
        artifacts = {root + f"?arch={abi}" for abi in ABIS}
        if not application_ref or not artifacts.issubset(graph.get(application_ref, set())):
            raise ValueError("SBOM application omits its native library dependencies")
        for abi, target in ABIS.items():
            identity = root + f"?arch={abi}"
            component = components[identity]
            props = properties(component)
            entry = f"lib/{abi}/{LIBRARY}"
            if props != {"zrotext:apk-entry": entry, "zrotext:rust-target": target} \
                    or component.get("purl") != identity or graph.get(identity) != {root} \
                    or not HEX.fullmatch(entries[entry]) \
                    or component.get("hashes") != [{"alg": "SHA-256", "content": entries[entry]}]:
                raise ValueError("Native inventory library differs from the APK")
        todo, reachable = [root], set()
        while todo:
            identity = todo.pop()
            if identity in reachable:
                continue
            if identity not in graph or identity not in components:
                raise ValueError("Native inventory dependency graph is incomplete")
            reachable.add(identity)
            todo.extend(graph[identity])
        native = {identity for identity, component in components.items()
                  if component.get("purl", "").startswith("pkg:cargo/")}
        if native != reachable | artifacts or not any(
                identity.startswith(f"pkg:cargo/{ROOT_MATERIAL}@") for identity in reachable):
            raise ValueError("Native inventory omits root material or has unreachable packages")
        for identity in reachable:
            component = components[identity]
            if component.get("purl") != identity or "?" in identity:
                raise ValueError("Native package identity is invalid")
            props = properties(component)
            features = {name for name in props if name.startswith("zrotext:cargo-features:")}
            if not features or not features.issubset({f"zrotext:cargo-features:{abi}" for abi in ABIS}):
                raise ValueError("Native package target features are missing")
            if identity == root and features != {f"zrotext:cargo-features:{abi}" for abi in ABIS}:
                raise ValueError("Native root package does not cover all Android targets")
            if "zrotext:workspace-source-commit" in props:
                if props["zrotext:workspace-source-commit"] != commit or "hashes" in component:
                    raise ValueError("Native workspace source identity differs")
            elif len(component.get("hashes", [])) != 1 \
                    or component["hashes"][0].get("alg") != "SHA-256" \
                    or not HEX.fullmatch(component["hashes"][0].get("content", "")):
                raise ValueError("Native registry checksum is missing")
        expected_nodes, expected_edges = packaged_components(manifest["packaged"], entries, commit)
        expected_refs = {component["bom-ref"] for component in expected_nodes}
        actual_refs = {identity for identity, component in components.items()
                       if component.get("purl", "").startswith("pkg:generic/")}
        if expected_refs != actual_refs:
            raise ValueError("Packaged native inventory identities are missing or unexpected")
        for component in expected_nodes:
            identity = component["bom-ref"]
            if components.get(identity) != component or graph.get(identity) != expected_edges[identity]:
                raise ValueError("Packaged native inventory source or library binding differs")
        packaged = manifest["packaged"]
        graphics_component(bom, packaged["graphics"])
        artifacts = {c["bom-ref"] for c in expected_nodes if "zrotext:apk-entry" in properties(c)}
        if not artifacts.issubset(graph.get(application_ref, set())):
            raise ValueError("SBOM application omits packaged native libraries")
        mapped = [properties(c)["zrotext:apk-entry"] for c in components.values()
                  if "zrotext:apk-entry" in properties(c)]
        expected = {f"lib/{abi}/{library}" for abi in ABIS for library in LIBRARIES}
        if len(mapped) != len(expected) or set(mapped) != expected:
            raise ValueError("Packaged native entries are missing or duplicated")
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ValueError("Native inventory is missing or malformed") from exc
