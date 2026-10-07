# SPDX-License-Identifier: AGPL-3.0-only
"""Add the locked native build graph and packaged libraries to CycloneDX.

Cargo's normal/build graph includes build dependencies and proc macros. It is
an intentionally conservative source inventory, not binary composition proof.
Only package identities, never Cargo's private local paths, enter the SBOM.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

ABIS = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "x86": "i686-linux-android",
}
ROOT_PACKAGE = "zrotext-android-owner-custody"
ROOT_MATERIAL = "zrotext-root-material"
LIBRARY = "libzrotext_android_owner_custody.so"
PROPERTY = "zrotext:native-build-inventory"
SCOPE = "locked normal/build dependency graph, including build dependencies and proc macros"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
HEX = re.compile(r"[0-9a-f]{64}\Z")
LINE = re.compile(r"(\d+)([A-Za-z0-9_-]+) v([A-Za-z0-9_.+-]+)([^|]*)\|([^|]*)\|([^|]*)\Z")


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


def merge_inventory(bom, lock_bytes, trees, entries, commit, repo):
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
    properties = result["metadata"].setdefault("properties", [])
    if any(prop.get("name") == PROPERTY for prop in properties):
        raise ValueError("SBOM already contains a native inventory")
    properties.append({"name": PROPERTY, "value": json.dumps({
        "version": 1, "source_commit": commit,
        "cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "root": root, "targets": ABIS, "scope": SCOPE,
    }, sort_keys=True, separators=(",", ":"))})
    verify_inventory(result, entries, commit)
    return result


def collect_inventory(bom, apk_entries, commit, repo, environment):
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
                           apk_entries, commit, repo)


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
        if set(manifest) != {"version", "source_commit", "cargo_lock_sha256", "root", "targets", "scope"} \
                or type(manifest["version"]) is not int or manifest["version"] != 1 or manifest["source_commit"] != commit \
                or manifest["targets"] != ABIS or manifest["scope"] != SCOPE \
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
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ValueError("Native inventory is missing or malformed") from exc
