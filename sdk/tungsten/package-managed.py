"""Archive and clean-consumer gates for npm, Maven, and NuGet candidates."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

CONFIG = Path(__file__).resolve().parent
MAVEN = "http://maven.apache.org/POM/4.0.0"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def wire_checks(command, env):
    spec = importlib.util.spec_from_file_location("installed_managed_wire", CONFIG / "package-wire/managed.py")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    checks.exercise(list(map(str, command)), env)


def executable(name):
    path = shutil.which(name + ".cmd" if os.name == "nt" and name in ("npm", "mvn") else name)
    if path is None:
        raise ValueError("Required tool unavailable: " + name)
    return path


def check_zip_license(path, expected, name):
    with zipfile.ZipFile(path) as archive:
        if archive.read(name) != expected:
            raise ValueError("Incorrect archive license")
        if any(part in ("..", "node_modules", ".git", "obj") for entry in archive.namelist()
               for part in entry.split("/")):
            raise ValueError("Unexpected package content")


def typescript_package(stage, feed):
    npm = executable("npm")
    sdk, runtime = stage / "sdk", stage / "runtime"
    manifest = json.loads((sdk / "package.json").read_text())
    manifest["license"] = "AGPL-3.0-only"
    manifest["files"] = ["dist", "LICENSE", "README.md"]
    (sdk / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.copy2(CONFIG / "typescript.package-lock.json", sdk / "package-lock.json")
    for project in (runtime, sdk):
        run(npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", cwd=project)
        if project == sdk:
            run(npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--no-save",
                next(feed.glob("elysra-tungsten-runtime-*.tgz")), cwd=project)
        run(npm, "run", "build", cwd=project)
        run(npm, "pack", "--ignore-scripts", "--pack-destination", feed, cwd=project)
        name = "elysra-tungsten-runtime" if project == runtime else "elysra-zrotext"
        with tarfile.open(next(feed.glob(name + "-*.tgz"))) as archive:
            if archive.extractfile("package/LICENSE").read() != (project / "LICENSE").read_bytes():
                raise ValueError("Incorrect npm license")
            allowed = ("package/LICENSE", "package/README.md", "package/package.json")
            if any((item.name not in allowed and not item.name.startswith("package/dist/"))
                   or not item.isfile() or ".." in item.name.split("/") for item in archive):
                raise ValueError("Unexpected npm archive content")
    shutil.rmtree(sdk)
    shutil.rmtree(runtime)
    consumer = stage / "consumer"
    consumer.mkdir()
    (consumer / "package.json").write_text('{"name":"zrotext-package-consumer","private":true,"type":"module"}\n')
    lock = json.loads((CONFIG / "typescript.package-lock.json").read_text())
    zod = lock["packages"]["node_modules/zod"]["version"]
    run(npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact",
        next(feed.glob("elysra-zrotext-*.tgz")), next(feed.glob("elysra-tungsten-runtime-*.tgz")),
        "zod@" + zod, "typescript@" + lock["packages"]["node_modules/typescript"]["version"], cwd=consumer)
    (consumer / "consumer.ts").write_text(
        "import { ZrotextClient } from '@elysra/zrotext';\n"
        "const client = new ZrotextClient({baseUrl:'https://sdk.example.invalid'});\n"
        "void [client.public, client.sealed, client.workflow];\n")
    run(executable("node"), consumer / "node_modules/typescript/bin/tsc", "--noEmit", "--strict",
        "--module", "NodeNext", "--target", "ES2022", "consumer.ts", cwd=consumer)
    env = {key: value for key, value in os.environ.items() if key not in ("NODE_PATH", "NODE_OPTIONS")}
    run(executable("node"), "--input-type=module", "-e",
        "import {ZrotextClient} from '@elysra/zrotext'; "
        "import {fileURLToPath} from 'node:url'; import {realpathSync} from 'node:fs'; "
        "for (const name of ['@elysra/zrotext','@elysra/tungsten-runtime']) {"
        "const file=realpathSync(fileURLToPath(import.meta.resolve(name)));"
        "if(!file.startsWith(realpathSync('node_modules')+'/') && "
        "!file.startsWith(realpathSync('node_modules')+'\\\\'))throw Error('source injection');}"
        "const c=new ZrotextClient({baseUrl:'https://sdk.example.invalid'});"
        "if(!c.public || !c.sealed || !c.workflow)throw Error('missing namespace');"
        "console.log('Installed npm client loaded');", cwd=consumer,
        env=env)
    # Keep the source contract cases identical, changing only their imports to
    # public package exports. Refuse drift instead of silently testing source.
    contracts = (CONFIG / "contract.test.mjs").read_text(encoding="utf-8")
    imports = ("import { ZrotextClient } from './generated/typescript/dist/client.js';\n"
               "import { operations, api } from './generated/typescript/dist/descriptors.js';")
    if contracts.count(imports) != 1:
        raise ValueError("Review changed TypeScript contract imports")
    contracts = contracts.replace(imports, "import { ZrotextClient, descriptors } from '@elysra/zrotext';\n"
                                 "const { operations, api } = descriptors;")
    (consumer / "contract.test.mjs").write_text(contracts, encoding="utf-8")
    shutil.copyfile(CONFIG / "package-wire/typescript.test.mjs", consumer / "wire.test.mjs")
    run(executable("node"), "--test", "contract.test.mjs", "wire.test.mjs", cwd=consumer, env=env)


def java_package(stage, feed):
    mvn = executable("mvn")
    ET.register_namespace("", MAVEN)
    tag = lambda name: "{" + MAVEN + "}" + name
    cache = stage / "build-cache"
    for name, group, artifact, license_id in (
        ("runtime", "io.github.pboachie.tungsten", "tungsten-runtime", "Apache-2.0"),
        ("sdk", "io.github.pboachie.zrotext", "zrotext-sdk", "AGPL-3.0-only"),
    ):
        project = stage / name
        tree = ET.parse(project / "pom.xml")
        root = tree.getroot()
        if root.find(tag("licenses")) is None:
            licenses = ET.SubElement(root, tag("licenses"))
            license_node = ET.SubElement(licenses, tag("license"))
            ET.SubElement(license_node, tag("name")).text = license_id
        plugins = root.find(tag("build") + "/" + tag("plugins"))
        for plugin_id, version in (("maven-resources-plugin", "3.3.1"),
                                   ("maven-jar-plugin", "3.4.2"),
                                   ("maven-surefire-plugin", "3.5.2"),
                                   ("maven-install-plugin", "3.1.3")):
            if any(p.findtext(tag("artifactId")) == plugin_id for p in plugins):
                continue
            plugin = ET.SubElement(plugins, tag("plugin"))
            ET.SubElement(plugin, tag("groupId")).text = "org.apache.maven.plugins"
            ET.SubElement(plugin, tag("artifactId")).text = plugin_id
            ET.SubElement(plugin, tag("version")).text = version
        tree.write(project / "pom.xml", encoding="utf-8", xml_declaration=True)
        resources = project / "src/main/resources/META-INF"
        resources.mkdir(parents=True, exist_ok=True)
        shutil.copy2(project / "LICENSE", resources / "LICENSE")
        run(mvn, "--batch-mode", "-Dmaven.repo.local=" + str(cache), "install", cwd=project)
        destination = feed / group.replace(".", "/") / artifact / "0.1.0"
        destination.mkdir(parents=True)
        jar = project / "target" / (artifact + "-0.1.0.jar")
        check_zip_license(jar, (project / "LICENSE").read_bytes(), "META-INF/LICENSE")
        shutil.copy2(jar, destination / jar.name)
        shutil.copy2(project / "pom.xml", destination / (artifact + "-0.1.0.pom"))
        for archive in list(destination.iterdir()):
            for algorithm in ("sha1", "sha256"):
                digest = hashlib.new(algorithm, archive.read_bytes()).hexdigest()
                archive.with_name(archive.name + "." + algorithm).write_text(digest + "\n")
    shutil.rmtree(stage / "runtime")
    shutil.rmtree(stage / "sdk")
    consumer = stage / "consumer"
    (consumer / "src/main/java").mkdir(parents=True)
    (consumer / "pom.xml").write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>consumer</artifactId><version>1</version>
<properties><maven.compiler.release>17</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
<repositories><repository><id>candidate-feed</id><url>''' + feed.as_uri() + '''</url></repository></repositories>
<dependencies><dependency><groupId>io.github.pboachie.zrotext</groupId><artifactId>zrotext-sdk</artifactId><version>0.1.0</version></dependency></dependencies>
<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.14.0</version></plugin>
<plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-resources-plugin</artifactId><version>3.3.1</version></plugin></plugins></build>
</project>''')
    (consumer / "src/main/java/Consumer.java").write_text('''import io.github.pboachie.zrotext.ZrotextClient;
import io.github.pboachie.tungsten.runtime.ClientOptions;
public class Consumer { public static void main(String[] args) {
var c = new ZrotextClient(ClientOptions.builder().baseUrl("https://sdk.example.invalid").build());
if(c.public_()==null || c.sealed_()==null || c.workflow()==null) throw new AssertionError();
System.out.println("Installed Maven client loaded"); } }''')
    run(mvn, "--batch-mode", "-Dmaven.repo.local=" + str(stage / "consumer-cache"), "compile",
        "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies", cwd=consumer)
    for archive in feed.rglob("*.jar"):
        installed = consumer / "target/dependency" / archive.name
        if installed.read_bytes() != archive.read_bytes():
            raise ValueError("Maven consumer resolved a different candidate archive")
    env = {key: value for key, value in os.environ.items()
           if key not in ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS")}
    run(executable("java"), "-cp", str(consumer / "target/classes") + os.pathsep
        + str(consumer / "target/dependency/*"), "Consumer", cwd=consumer, env=env)
    classes = consumer / "wire-classes"
    classes.mkdir()
    classpath = str(consumer / "target/dependency/*")
    run(executable("javac"), "--release", "17", "-Xlint:all", "-Werror", "-cp", classpath,
        "-d", classes, CONFIG / "package-wire/Probe.java", cwd=consumer, env=env)
    wire_checks([executable("java"), "-cp", str(classes) + os.pathsep + classpath, "Probe"], env)


def csharp_package(stage, feed):
    dotnet = executable("dotnet")
    config = stage / "NuGet.Config"
    # Local coordinates are mapped exclusively to the candidate feed. Ordinary
    # SDK build dependencies remain available from NuGet without permitting a
    # registry copy to mask a missing candidate archive.
    xml = ET.Element("configuration")
    sources = ET.SubElement(xml, "packageSources")
    ET.SubElement(sources, "clear")
    ET.SubElement(sources, "add", key="candidate", value=str(feed))
    ET.SubElement(sources, "add", key="nuget", value="https://api.nuget.org/v3/index.json")
    mapping = ET.SubElement(xml, "packageSourceMapping")
    local = ET.SubElement(mapping, "packageSource", key="candidate")
    for pattern in ("Tungsten.Runtime", "Zrotext.Sdk"):
        ET.SubElement(local, "package", pattern=pattern)
    public = ET.SubElement(mapping, "packageSource", key="nuget")
    ET.SubElement(public, "package", pattern="Microsoft.*")
    ET.ElementTree(xml).write(config, encoding="utf-8", xml_declaration=True)
    env = dict(os.environ, NUGET_PACKAGES=str(stage / "build-cache"),
               DOTNET_CLI_HOME=str(stage / "dotnet-home"), DOTNET_NOLOGO="1")
    for name, project_file, archive_name in (
        ("runtime", "Tungsten.Runtime.csproj", "Tungsten.Runtime.0.1.1.nupkg"),
        ("sdk", "Zrotext.Sdk.csproj", "Zrotext.Sdk.0.1.0.nupkg"),
    ):
        project = stage / name
        path = project / project_file
        tree = ET.parse(path)
        root = tree.getroot()
        properties = root.find("PropertyGroup")
        if name == "sdk":
            ET.SubElement(properties, "PackageLicenseExpression").text = "AGPL-3.0-only"
        ET.SubElement(properties, "PathMap").text = str(stage) + "=/_/"
        item = ET.SubElement(root, "ItemGroup")
        ET.SubElement(item, "None", Update="LICENSE", Pack="true", PackagePath="")
        if (project / "README.md").exists():
            ET.SubElement(properties, "PackageReadmeFile").text = "README.md"
            ET.SubElement(item, "None", Update="README.md", Pack="true", PackagePath="")
        tree.write(path, encoding="utf-8", xml_declaration=True)
        run(dotnet, "restore", path, "--configfile", config, env=env, cwd=stage)
        run(dotnet, "pack", path, "--no-restore", "-c", "Release", "--output", feed, env=env, cwd=stage)
        check_zip_license(feed / archive_name, (project / "LICENSE").read_bytes(), "LICENSE")
    shutil.rmtree(stage / "runtime")
    shutil.rmtree(stage / "sdk")
    consumer = stage / "consumer"
    consumer.mkdir()
    (consumer / "Consumer.csproj").write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
<OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup>
<ItemGroup><PackageReference Include="Zrotext.Sdk" Version="0.1.0" /></ItemGroup></Project>''')
    (consumer / "Program.cs").write_text('''var client = new Zrotext.Sdk.ZrotextClient();
if (client.Public is null || client.Sealed is null || client.Workflow is null) throw new System.Exception();
System.Console.WriteLine("Installed NuGet client loaded");''')
    env["NUGET_PACKAGES"] = str(stage / "consumer-cache")
    run(dotnet, "restore", consumer / "Consumer.csproj", "--configfile", config, env=env, cwd=consumer)
    run(dotnet, "run", "--project", consumer / "Consumer.csproj", "--no-restore", "-c", "Release",
        env=env, cwd=consumer)
    shutil.copyfile(CONFIG / "package-wire/Probe.cs", consumer / "Program.cs")
    run(dotnet, "build", consumer / "Consumer.csproj", "--no-restore", "-t:Rebuild", "-c", "Release",
        env=env, cwd=consumer)
    wire_checks([dotnet, consumer / "bin/Release/net10.0/Consumer.dll"], env)
