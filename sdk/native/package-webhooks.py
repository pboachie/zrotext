"""Build managed webhook archives and verify isolated installed consumers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "sdk/native"
VERSION = "0.1.0-alpha.1"
MAVEN = "http://maven.apache.org/POM/4.0.0"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def tool(name):
    result = shutil.which(name + ".cmd" if os.name == "nt" and name == "mvn" else name)
    if not result:
        raise ValueError("Required tool not found: " + name)
    return result


def clean_env():
    return {key: value for key, value in os.environ.items() if key not in
            ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "RUBYOPT", "RUBYLIB", "DOTNET_STARTUP_HOOKS")}


def check_zip(path, license_path, expected, license_bytes):
    with zipfile.ZipFile(path) as archive:
        files = [info.filename for info in archive.infolist() if not info.is_dir()]
        if len(files) != len(set(files)) or set(files) != expected:
            raise ValueError("Unexpected archive file inventory: " + path.name + " " + repr(files))
        if archive.read(license_path) != license_bytes:
            raise ValueError("Archive license mismatch")


def java(stage, source, feed, env):
    mvn = tool("mvn")
    resources = source / "resources/META-INF"
    resources.mkdir(parents=True)
    for name in ("LICENSE", "README.md"):
        shutil.copyfile(source / name, resources / name)
    run(mvn, "--batch-mode", "-Dmaven.repo.local=" + str(stage / "build-cache"), "package", cwd=source, env=env)
    archive = source / "target" / ("zrotext-webhooks-" + VERSION + ".jar")
    expected = {"META-INF/MANIFEST.MF", "META-INF/LICENSE", "META-INF/README.md",
                "org/zrotext/Webhook.class", "org/zrotext/Webhook$VerificationException.class"}
    expected |= {"META-INF/maven/io.github.pboachie.zrotext/zrotext-webhooks/" + name for name in ("pom.xml", "pom.properties")}
    check_zip(archive, "META-INF/LICENSE", expected, (source / "LICENSE").read_bytes())
    destination = feed / "io/github/pboachie/zrotext/zrotext-webhooks" / VERSION
    destination.mkdir(parents=True)
    shutil.copyfile(archive, destination / archive.name)
    shutil.copyfile(source / "pom.xml", destination / ("zrotext-webhooks-" + VERSION + ".pom"))
    for file in list(destination.iterdir()):
        for algorithm in ("sha1", "sha256"):
            file.with_name(file.name + "." + algorithm).write_text(hashlib.new(algorithm, file.read_bytes()).hexdigest())
    consumer = stage / "consumer"
    (consumer / "src/main/java").mkdir(parents=True)
    shutil.copyfile(source / "test/WebhookTest.java", consumer / "src/main/java/WebhookTest.java")
    # Ordinary Maven coordinates, pinned compiler plugins and a fresh cache.
    ET.register_namespace("", MAVEN)
    tag = lambda name: "{" + MAVEN + "}" + name
    tree = ET.parse(source / "pom.xml"); root = tree.getroot()
    root.find(tag("artifactId")).text = "consumer"
    build = root.find(tag("build"));build.remove(build.find(tag("sourceDirectory")))
    build.remove(build.find(tag("resources")))
    repositories = ET.SubElement(root, tag("repositories")); repo = ET.SubElement(repositories, tag("repository"))
    ET.SubElement(repo, tag("id")).text = "candidate"; ET.SubElement(repo, tag("url")).text = feed.as_uri()
    dependencies = ET.SubElement(root, tag("dependencies")); dependency = ET.SubElement(dependencies, tag("dependency"))
    for key, value in (("groupId", "io.github.pboachie.zrotext"), ("artifactId", "zrotext-webhooks"), ("version", VERSION)):
        ET.SubElement(dependency, tag(key)).text = value
    tree.write(consumer / "pom.xml", encoding="utf-8", xml_declaration=True)
    shutil.rmtree(source)
    run(mvn, "--batch-mode", "-Dmaven.repo.local=" + str(stage / "consumer-cache"), "compile",
        "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies", cwd=consumer, env=env)
    installed = consumer / "target/dependency" / archive.name
    if installed.read_bytes() != (destination / archive.name).read_bytes():
        raise ValueError("Maven resolved another archive")
    run(tool("java"), "-cp", str(consumer / "target/classes") + os.pathsep + str(installed),
        "WebhookTest", stage / "vectors.tsv", cwd=consumer, env=env)


def csharp(stage, source, feed, env):
    dotnet = tool("dotnet")
    config = stage / "NuGet.Config"
    config.write_text('<configuration><packageSources><clear/><add key="candidate" value="' + str(feed) +
        '"/><add key="nuget" value="https://api.nuget.org/v3/index.json"/></packageSources>'
        '<packageSourceMapping><packageSource key="candidate"><package pattern="Zrotext.Webhooks"/></packageSource>'
        '<packageSource key="nuget"><package pattern="Microsoft.*"/></packageSource></packageSourceMapping></configuration>')
    env = dict(env, NUGET_PACKAGES=str(stage / "build-cache"), DOTNET_CLI_HOME=str(stage / "dotnet-home"), DOTNET_NOLOGO="1")
    run(dotnet, "pack", source / "Zrotext.Webhooks.csproj", "-c", "Release", "--output", feed,
        "--configfile", config, "-p:PathMap=" + str(stage) + "=/_/", cwd=stage, env=env)
    archive = feed / ("Zrotext.Webhooks." + VERSION + ".nupkg")
    with zipfile.ZipFile(archive) as packed:
        metadata = {name for name in packed.namelist() if name.startswith("package/services/metadata/core-properties/") and name.endswith(".psmdcp")}
    if len(metadata) != 1:
        raise ValueError("Unexpected NuGet metadata")
    check_zip(archive, "LICENSE", metadata | {"_rels/.rels", "[Content_Types].xml", "Zrotext.Webhooks.nuspec",
              "lib/net8.0/Zrotext.Webhooks.dll", "LICENSE", "README.md"}, (source / "LICENSE").read_bytes())
    consumer = stage / "consumer"; consumer.mkdir()
    shutil.copyfile(source / "tests/Program.cs", consumer / "Program.cs")
    vectors = consumer / "sdk/native"; vectors.mkdir(parents=True)
    shutil.copyfile(stage / "vectors.tsv", vectors / "webhook-vectors.tsv")
    project = consumer / "Consumer.csproj"
    project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        '<TargetFramework>net8.0</TargetFramework><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings>'
        '<TreatWarningsAsErrors>true</TreatWarningsAsErrors><RollForward>Major</RollForward></PropertyGroup>'
        '<ItemGroup><PackageReference Include="Zrotext.Webhooks" Version="' + VERSION + '"/></ItemGroup></Project>')
    shutil.rmtree(source)
    env["NUGET_PACKAGES"] = str(stage / "consumer-cache")
    run(dotnet, "restore", project, "--configfile", config, cwd=consumer, env=env)
    installed = Path(env["NUGET_PACKAGES"]) / "zrotext.webhooks" / VERSION / ("zrotext.webhooks." + VERSION + ".nupkg")
    if installed.read_bytes() != archive.read_bytes():
        raise ValueError("NuGet resolved another archive")
    run(dotnet, "run", "--project", project, "--no-restore", "-c", "Release", cwd=consumer, env=env)


def ruby(stage, source, feed, env):
    executable = tool("ruby")
    run(executable, "-rrubygems/gem_runner", "-e", "Gem::GemRunner.new.run(ARGV)", "--", "build", "zrotext-webhooks.gemspec", cwd=source, env=env)
    archive = next(source.glob("*.gem")); shutil.copyfile(archive, feed / archive.name)
    run(executable, "-rrubygems/package", "-e",
        "p=Gem::Package.new(ARGV[0]); p.verify; abort 'archive inventory' unless p.contents.sort == %w[LICENSE README.md lib/zrotext/webhook.rb].sort",
        archive, cwd=source, env=env)
    with tarfile.open(archive) as gem:
        payload = gem.extractfile("data.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as data:
        entries = data.getmembers()
        expected = {"LICENSE", "README.md", "lib/zrotext/webhook.rb"}
        if len(entries) != len(expected) or {entry.name for entry in entries} != expected:
            raise ValueError("Unexpected gem payload")
        for entry in entries:
            if not entry.isfile() or data.extractfile(entry).read() != (source / entry.name).read_bytes():
                raise ValueError("Gem payload differs from reviewed source")
    tests = (source / "test_webhook.rb").read_text()
    old = "require_relative 'lib/zrotext/webhook'"
    if tests.count(old) != 1:
        raise ValueError("Review changed Ruby test imports")
    consumer = stage / "consumer"; consumer.mkdir()
    (consumer / "test.rb").write_text(tests.replace(old, "require 'zrotext/webhook'"))
    shutil.rmtree(source)
    env = dict(env, GEM_HOME=str(stage / "gems"), GEM_PATH=str(stage / "gems"))
    run(executable, "-rrubygems/gem_runner", "-e", "Gem::GemRunner.new.run(ARGV)", "--", "install", "--local", "--no-document", feed / archive.name, cwd=consumer, env=env)
    run(executable, "-rzrotext/webhook", "-e",
        "p=$LOADED_FEATURES.find{|f| f.end_with?('/zrotext/webhook.rb')}; abort 'outside installed gem' unless File.realpath(p).start_with?(File.realpath(ENV.fetch('GEM_HOME'))+File::SEPARATOR)", cwd=consumer, env=env)
    run(executable, consumer / "test.rb", stage / "vectors.tsv", cwd=consumer, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("java", "csharp", "ruby"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); output = args.out.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError("Use a new external artifact directory")
    with tempfile.TemporaryDirectory(prefix="zrotext-webhook-packages-") as directory:
        stage = Path(directory); source = stage / "source"; feed = stage / "feed"; feed.mkdir()
        # Copy tracked source paths only; build caches never become package input.
        paths = run("git", "ls-files", "--", "sdk/native/" + args.target, cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        for name in paths:
            relative = Path(name).relative_to("sdk/native/" + args.target)
            destination = source / relative; destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
        (source / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n"))
        shutil.copyfile(NATIVE / "webhook-vectors.tsv", stage / "vectors.tsv")
        globals()[args.target](stage, source, feed, clean_env())
        shutil.copytree(feed, output)
    report = {"target": args.target, "qualification": "isolated installed webhook vectors; no registry publication or sealed/device acceptance",
              "sha256": {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in output.rglob("*") if p.is_file()}}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(args.target + " webhook archive and installed vector consumer passed")


if __name__ == "__main__":
    main()
