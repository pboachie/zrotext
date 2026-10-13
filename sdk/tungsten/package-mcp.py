"""Build a bounded guarded MCP npm archive and exercise its installed entry point."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "sdk/tungsten"
UNITS = ("draft01", "workflow-tool-client", "workflow-tools", "workflow-decisions")


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Review changed guarded acceptance imports")
    return text.replace(old, new)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError("Use a new external artifact directory")
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    node = shutil.which("node")
    if not npm or not node:
        raise ValueError("Node and npm are required")
    # Read only reviewed generated files; no raw generated MCP server is packaged.
    spec = importlib.util.spec_from_file_location("mcp_source_inventory", CONFIG / "package-sources.py")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    generated = policy.reviewed_files(CONFIG / "generated", json.loads((CONFIG / "generated.lock.json").read_text()))
    catalog = generated["mcp"]["manifest.json"]
    lock = json.loads((ROOT / "sdk/typescript/package-lock.json").read_text())
    hpke = lock["packages"]["node_modules/@hpke/core"]["version"]
    env = {key: value for key, value in os.environ.items()
           if key not in ("NODE_PATH", "NODE_OPTIONS") and not key.startswith("ZROTEXT_")}
    with tempfile.TemporaryDirectory(prefix="zrotext-guarded-mcp-") as directory:
        stage = Path(directory)
        build = stage / "build"
        (build / "src").mkdir(parents=True)
        for name in ("package.json", "package-lock.json", "tsconfig.json"):
            shutil.copyfile(ROOT / "sdk/typescript" / name, build / name)
        for name in UNITS:
            shutil.copyfile(ROOT / "sdk/typescript/src" / (name + ".ts"), build / "src" / (name + ".ts"))
        run(npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", cwd=build, env=env)
        run(npm, "run", "build", cwd=build, env=env)
        package = stage / "package"
        package.mkdir()
        files = {}
        for path in ("sdk/mcp/server.mjs", "sdk/tungsten/mcp/server.mjs", "sdk/tungsten/mcp/adapter.mjs"):
            files["lib/" + path] = (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
        for name in UNITS:
            files["lib/sdk/typescript/dist/" + name + ".js"] = (build / "dist" / (name + ".js")).read_bytes()
        files["lib/sdk/tungsten/generated/mcp/manifest.json"] = catalog
        files["LICENSE"] = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
        files["README.md"] = (CONFIG / "mcp/README.md").read_bytes().replace(b"\r\n", b"\n")
        manifest = dict(name="@elysra/zrotext-mcp", version="0.1.0-alpha.1", type="module",
                        description="Guarded local ZROtext workflow MCP adapter candidate",
                        license="AGPL-3.0-only", engines={"node": ">=22"},
                        files=["lib", "LICENSE", "README.md", "npm-shrinkwrap.json"],
                        dependencies={"@hpke/core": hpke},
                        bin={"zrotext-mcp": "lib/sdk/tungsten/mcp/server.mjs"},
                        exports={".": "./lib/sdk/tungsten/mcp/adapter.mjs",
                                 "./stdio": "./lib/sdk/tungsten/mcp/server.mjs"})
        files["package.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        shrinkwrap = {"name": manifest["name"], "version": manifest["version"],
                      "lockfileVersion": 3, "requires": True,
                      "packages": {"": {key: manifest[key] for key in
                                         ("name", "version", "license", "dependencies", "bin", "engines")}}}
        for name, entry in lock["packages"].items():
            if name and not entry.get("dev", False):
                shrinkwrap["packages"][name] = entry
        files["npm-shrinkwrap.json"] = (json.dumps(shrinkwrap, indent=2) + "\n").encode()
        for name, content in files.items():
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        feed = stage / "feed"
        feed.mkdir()
        run(npm, "pack", "--ignore-scripts", "--pack-destination", feed, cwd=package, env=env)
        archive = next(feed.glob("*.tgz"))
        with tarfile.open(archive) as packed:
            entries = packed.getmembers()
            if {entry.name for entry in entries} != {"package/" + name for name in files}:
                raise ValueError("Unexpected guarded MCP archive contents")
            for entry in entries:
                if not entry.isfile() or packed.extractfile(entry).read() != files[entry.name[len("package/"):]]:
                    raise ValueError("Guarded MCP archive differs from staged content")
        shutil.rmtree(build)
        shutil.rmtree(package)
        consumer = stage / "consumer"
        consumer.mkdir()
        (consumer / "package.json").write_text('{"private":true,"type":"module"}\n')
        run(npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", archive, cwd=consumer, env=env)
        # Adapter controls retain identical assertions and use
        # installed public exports or the packaged guarded comparison fixture.
        tests = (CONFIG / "mcp/adapter.test.mjs").read_text()
        tests = replace_once(tests, "from './adapter.mjs'", "from '@elysra/zrotext-mcp'")
        tests = replace_once(tests, "from '../../mcp/server.mjs'",
                             "from './node_modules/@elysra/zrotext-mcp/lib/sdk/mcp/server.mjs'")
        tests = replace_once(tests, "from '../../typescript/dist/workflow-tool-client.js'",
                             "from './node_modules/@elysra/zrotext-mcp/lib/sdk/typescript/dist/workflow-tool-client.js'")
        tests = replace_once(tests, "from './server.mjs'", "from '@elysra/zrotext-mcp/stdio'")
        tests = replace_once(tests, "new URL('./server.mjs', import.meta.url)",
                             "new URL(import.meta.resolve('@elysra/zrotext-mcp/stdio'))")
        (consumer / "adapter.test.mjs").write_text(tests, encoding="utf-8")
        shutil.copyfile(CONFIG / "package-wire/mcp.test.mjs", consumer / "installed.test.mjs")
        run(node, "--test", "adapter.test.mjs", "installed.test.mjs", cwd=consumer, env=env)
        output.mkdir(parents=True)
        shutil.copyfile(archive, output / archive.name)
        report = {"name": manifest["name"], "version": manifest["version"],
                  "qualification": "installed guarded local stdio; no live authority or publication",
                  "sha256": {archive.name: hashlib.sha256(archive.read_bytes()).hexdigest()},
                  "catalog_sha256": hashlib.sha256(catalog).hexdigest()}
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Guarded MCP archive and isolated installed acceptance passed; no publication performed")


if __name__ == "__main__":
    main()
