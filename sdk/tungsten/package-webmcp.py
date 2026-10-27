"""Build a bounded experimental WebMCP npm archive and exercise installed native browser registration."""
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
UNITS = ("workflow-tools", "workflow-decisions", "workflow-tool-client")


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
    # Verify the complete reviewed generated inventory before packaging the catalog.
    spec = importlib.util.spec_from_file_location("mcp_source_inventory", CONFIG / "package-sources.py")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    generated = policy.reviewed_files(CONFIG / "generated", json.loads((CONFIG / "generated.lock.json").read_text()))
    catalog = generated["webmcp"]["manifest.json"]
    env = {key: value for key, value in os.environ.items()
           if key not in ("NODE_PATH", "NODE_OPTIONS") and not key.startswith("ZROTEXT_")}
    with tempfile.TemporaryDirectory(prefix="zrotext-experimental-webmcp-") as directory:
        stage = Path(directory)
        build = stage / "build"
        (build / "src").mkdir(parents=True)
        for name in ("package.json", "package-lock.json", "tsconfig.json"):
            shutil.copyfile(ROOT / "sdk/typescript" / name, build / name)
        for name in UNITS:
            shutil.copyfile(ROOT / "sdk/typescript/src" / (name + ".ts"), build / "src" / (name + ".ts"))
        run(npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", cwd=build, env=env)
        # This closed subset has no contact modules or generated IDNA assets.
        run(node, build / "node_modules/typescript/bin/tsc", "-p", "tsconfig.json", cwd=build, env=env)
        package = stage / "package"
        package.mkdir()
        files = {}
        for path in ("sdk/tungsten/webmcp/index.mjs", "sdk/tungsten/webmcp/app/server.mjs",
                     "sdk/tungsten/webmcp/app/app.mjs", "sdk/tungsten/webmcp/app/index.html",
                     "sdk/tungsten/webmcp/app/README.md", "sdk/tungsten/generated.lock.json"):
            files["lib/" + path] = (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
        for name in UNITS:
            files["lib/sdk/typescript/dist/" + name + ".js"] = (build / "dist" / (name + ".js")).read_bytes()
        files["lib/sdk/tungsten/generated/webmcp/manifest.json"] = catalog
        files["LICENSE"] = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
        files["README.md"] = (CONFIG / "webmcp/README.md").read_bytes().replace(b"\r\n", b"\n")
        manifest = dict(name="@elysra/zrotext-webmcp", version="0.1.0-alpha.1", type="module",
                        description="Experimental opt-in ZROtext browser workflow adapter",
                        license="AGPL-3.0-only", engines={"node": ">=22"},
                        files=["lib", "LICENSE", "README.md"],
                        bin={"zrotext-webmcp-app": "./lib/sdk/tungsten/webmcp/app/server.mjs"},
                        exports={".": "./lib/sdk/tungsten/webmcp/index.mjs",
                                 "./app": "./lib/sdk/tungsten/webmcp/app/server.mjs",
                                 "./catalog": "./lib/sdk/tungsten/generated/webmcp/manifest.json"})
        files["package.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
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
                raise ValueError("Unexpected experimental WebMCP archive contents")
            for entry in entries:
                if not entry.isfile() or packed.extractfile(entry).read() != files[entry.name[len("package/"):]]:
                    raise ValueError("Experimental WebMCP archive differs from staged content")
        shutil.rmtree(build)
        shutil.rmtree(package)
        consumer = stage / "consumer"
        consumer.mkdir()
        # Install the exact browser-test development graph, never a runtime dependency.
        browser_lock = json.loads((ROOT / "web/owner/package-lock.json").read_text())
        (consumer / "package.json").write_bytes((ROOT / "web/owner/package.json").read_bytes())
        (consumer / "package-lock.json").write_text(json.dumps(browser_lock))
        run(npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", cwd=consumer, env=env)
        run(npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", archive, cwd=consumer, env=env)
        tests = (CONFIG / "webmcp/adapter.test.mjs").read_text()
        tests = replace_once(tests, "from './index.mjs'", "from '@elysra/zrotext-webmcp'")
        tests = replace_once(tests, "import('./index.mjs?no-browser-effects')",
                             "import(import.meta.resolve('@elysra/zrotext-webmcp') + '?no-browser-effects')")
        tests = replace_once(tests, "from '../../typescript/dist/workflow-tools.js'",
                             "from './node_modules/@elysra/zrotext-webmcp/lib/sdk/typescript/dist/workflow-tools.js'")
        (consumer / "adapter.test.mjs").write_text(tests, encoding="utf-8")
        browser = (CONFIG / "webmcp/browser.test.mjs").read_text()
        browser = replace_once(browser, "new URL('../../../web/owner/package.json', import.meta.url)",
                               "new URL('./package.json', import.meta.url)")
        browser = replace_once(browser, "new URL('../../../', import.meta.url)",
                               "new URL('./node_modules/@elysra/zrotext-webmcp/lib/', import.meta.url)")
        browser = replace_once(browser, "  const files = new Map([", "  const files = new Map([\n"
            "    ['/catalog.json', new URL('sdk/tungsten/generated/webmcp/manifest.json', root)],")
        browser = replace_once(browser,
            "manifest: { catalogVersion: 1, api: 'zrotext', tools: [{ name, target: 'workflow.contact.read', kind: 'operation' }] },",
            "manifest: state.catalog,")
        browser = replace_once(browser, "      state.register = () => registerWorkflowTools({",
            "      state.catalog = await (await fetch('/catalog.json')).json();\n"
            "      state.register = () => registerWorkflowTools({")
        (consumer / "browser.test.mjs").write_text(browser, encoding="utf-8")
        application = (CONFIG / "webmcp/app/app.test.mjs").read_text()
        application = replace_once(application, "from './server.mjs'", "from '@elysra/zrotext-webmcp/app'")
        application = replace_once(application, "new URL('../../../../web/owner/package.json', import.meta.url)",
                                   "new URL('./package.json', import.meta.url)")
        application = replace_once(application, "new URL('./server.mjs', import.meta.url)",
                                   "new URL('./node_modules/@elysra/zrotext-webmcp/lib/sdk/tungsten/webmcp/app/server.mjs', import.meta.url)")
        (consumer / "app.test.mjs").write_text(application, encoding="utf-8")
        capability = (CONFIG / "webmcp/app/capability.test.mjs").read_text()
        capability = replace_once(capability, "from './server.mjs'", "from '@elysra/zrotext-webmcp/app'")
        capability = replace_once(capability, "new URL('../../../../web/owner/package.json', import.meta.url)",
                                  "new URL('./package.json', import.meta.url)")
        (consumer / "capability.test.mjs").write_text(capability, encoding="utf-8")
        browser_report = stage / "browser-qualification.json"
        env["ZT_WEBMCP_BROWSER_REPORT"] = str(browser_report)
        run(node, "--test", "adapter.test.mjs", "browser.test.mjs", "app.test.mjs", "capability.test.mjs", cwd=consumer, env=env)
        output.mkdir(parents=True)
        shutil.copyfile(archive, output / archive.name)
        report = {"name": manifest["name"], "version": manifest["version"],
                  "qualification": "installed native browser and authenticated HTTPS application; synthetic workflow upstream; no publication",
                  "sha256": {archive.name: hashlib.sha256(archive.read_bytes()).hexdigest()},
                  "catalog_sha256": hashlib.sha256(catalog).hexdigest(),
                  "browser_capabilities": json.loads(browser_report.read_text())}
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Experimental WebMCP archive and isolated installed acceptance passed; no publication performed")


if __name__ == "__main__":
    main()
