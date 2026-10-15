"""Compile Java/C# or load Ruby against the verified runtime source.

Temporary source dependency overrides do not prove registry installation.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", choices=["java", "csharp", "ruby"], required=True)
    parser.add_argument("--ruby", default="ruby", help="Ruby executable (3.3 or newer)")
    args = parser.parse_args()
    source = args.source.resolve()
    spec = importlib.util.spec_from_file_location("generation_policy", ROOT / "scripts/tungsten_sdk.py")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    config = ROOT / "sdk/tungsten"
    policy.verify_source(source, json.loads((config / "generator.lock.json").read_text()))
    with tempfile.TemporaryDirectory(prefix="zrotext-managed-source-check-") as temp:
        stage = Path(temp)
        sdk = stage / "sdk"
        shutil.copytree(config / "generated" / args.target, sdk,
                        ignore=shutil.ignore_patterns("bin", "obj", "target"))
        runtime = stage / "runtime"
        shutil.copytree(source / "runtimes" / args.target, runtime,
                        ignore=shutil.ignore_patterns("bin", "obj", "target"))
        if args.target == "java":
            sources = list((sdk / "src").rglob("*.java")) + list((runtime / "src").rglob("*.java"))
            run("javac", "--release", "17", "-Xlint:all", "-Werror", "-d", stage / "classes", *sources)
        elif args.target == "csharp":
            project = next(sdk.glob("*.csproj"))
            original = project.read_text(encoding="utf-8")
            package = '<PackageReference Include="Tungsten.Runtime" Version="0.1.1" />'
            if original.count(package) != 1:
                raise ValueError("Unexpected C# runtime declaration")
            project.write_text(original.replace(package,
                '<ProjectReference Include="../runtime/Tungsten.Runtime.csproj" />'), encoding="utf-8")
            run("dotnet", "build", project, "--nologo")
        else:
            run(args.ruby, "-I", runtime / "lib", "-I", sdk / "lib", "-rzrotext_sdk", "-e",
                "abort 'Ruby 3.3 required' if (RUBY_VERSION.split('.').map(&:to_i)[0,2] <=> [3,3]) < 0; puts ZrotextSdk::VERSION")
    print(args.target + " source-runtime check passed; registry and live HTTP were not tested")


if __name__ == "__main__":
    main()
