"""Build candidate native archives, remove staging, and exercise installed consumers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
VERSION = "0.1.0-alpha.1"
JAVA_ID = "zrotext-native-candidate"
CS_ID = "Zrotext.Native.Candidate"
RUBY_ID = "zrotext-native-candidate"
MODULES = ["HpkeRecipient", "SignedEnvelope", "ManifestChain", "Election03",
           "SealedReader02", "ElectedReader03", "OriginalReplyReader", "ProtectedRecipient", "ProtectedSigner",
           "Compose03", "Compose02", "RootJournal", "ElectionJournal", "CandidateBody",
           "OriginalReplyCheckpoint", "OriginalHttp", "OriginalCurrentClient"]
SUITES = {"root-journal": "RootJournalTest", "election-journal": "ElectionJournalTest",
          "custody": "CustodyTest", "composition": "ComposeTest", "composition02": "Compose02Test",
          "original-reply": "OriginalReplyTest", "original-protected": "OriginalProtectedTest",
          "original-history": "OriginalHistoryTest", "http": "HttpTest", "current-http": "CurrentTest"}
PINS = {"producer02": "a13ea1e3d6f6db594485c19b36c43fe642e67c7a",
        "producer03": "304d512b7a420a3102278f32baed095f3e778989",
        "custody_producer": "a5fb59c2c5bc81e80b5b8d4b836afd51c5304653",
        "root_producer": "93a65d737dfb0de603c732241c667f90771f60dd",
        "root_controls": "26e73753c4ff5e3b27abdca6f5b67ed3ce5a0273",
        "controls": "1b7732ec36bf705f78e69a2cea95b792f04dc772",
        "original_producer": "72124e1a3ff28e782f870eeddbdc33cacf8ca3b4",
        "http_fixture": "6307413ae33fa4623483ca5adf306045b3efffb1",
        "current_fixture": "50c7258eb7e616ba8f0574d167bff7b999a9bd8d"}


def run(*args, **kw):
    return subprocess.run([str(x) for x in args], check=True, **kw)


def tool(name):
    found = shutil.which(name + ".cmd" if os.name == "nt" and name == "mvn" else name)
    if not found:
        raise ValueError("Missing tool: " + name)
    return found


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def copy(path, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))


def env_clean():
    blocked = {"CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
               "RUBYOPT", "RUBYLIB", "DOTNET_STARTUP_HOOKS", "NODE_OPTIONS", "NODE_PATH"}
    return {k: v for k, v in os.environ.items() if k not in blocked}


def runtime_sources(target):
    extension = {"java": "java", "csharp": "cs", "ruby": "rb"}[target]
    result = []
    for module in MODULES:
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", module).lower() if target == "ruby" else module
        if target == 'ruby' and module == 'OriginalCurrentClient':
            name = 'original_current'
        candidates = list((HERE / target).rglob(name + "." + extension))
        if module == "CandidateBody":
            candidates = [HERE.parent / "crypto-candidate" / target / (name + "." + extension)]
        if len(candidates) != 1 or not candidates[0].is_file():
            raise ValueError("Closed runtime inventory changed: " + module)
        result.append(candidates[0])
    return result


def check_zip(path, expected, license_name, license_bytes):
    with zipfile.ZipFile(path) as archive:
        files = [i.filename for i in archive.infolist() if not i.is_dir()]
        if len(files) != len(set(files)) or set(files) != expected:
            raise ValueError("Unexpected package inventory: " + repr(files))
        if archive.read(license_name) != license_bytes:
            raise ValueError("Package license mismatch")


def java(stage, source, feed, env):
    mvn = tool("mvn")
    for path in runtime_sources("java"):
        copy(path, source / "src" / path.name)
    for name in ("LICENSE", "README.md"):
        copy(source / name, source / "resources/META-INF" / name)
    header = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
              '<groupId>io.github.pboachie.zrotext</groupId><artifactId>{}</artifactId><version>' + VERSION + '</version>'
              '<name>ZROtext native candidate</name><description>Experimental sealed companions</description>'
              '<url>https://github.com/pboachie/zrotext</url><licenses><license><name>AGPL-3.0-only</name>'
              '<url>https://www.gnu.org/licenses/agpl-3.0.html</url></license></licenses>'
              '<properties><maven.compiler.release>17</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>')
    plugins = '<plugins>' + ''.join('<plugin><groupId>org.apache.maven.plugins</groupId><artifactId>' + name + '</artifactId><version>' + version + '</version>' + config + '</plugin>' for name, version, config in (
        ('maven-compiler-plugin', '3.14.0', '<configuration><compilerArgs><arg>-Xlint:all</arg><arg>-Werror</arg></compilerArgs></configuration>'),
        ('maven-resources-plugin', '3.3.1', ''), ('maven-jar-plugin', '3.4.2', ''), ('maven-surefire-plugin', '3.5.2', ''))) + '</plugins>'
    dependency = '<dependency><groupId>{}</groupId><artifactId>{}</artifactId><version>{}</version></dependency>'
    jna = dependency.format('net.java.dev.jna', 'jna', '5.17.0')
    gson = dependency.format('com.google.code.gson', 'gson', '2.14.0')
    annotations = dependency.format('com.google.errorprone', 'error_prone_annotations', '2.48.0')
    write(source / 'pom.xml', header.format(JAVA_ID) + '<dependencies>' + jna + gson + annotations + '</dependencies><build><sourceDirectory>src</sourceDirectory><resources><resource><directory>resources</directory></resource></resources>' + plugins + '</build></project>')
    run(mvn, '--batch-mode', '-Dmaven.repo.local=' + str(stage / 'build-cache'), 'package', cwd=source, env=env)
    name = JAVA_ID + '-' + VERSION + '.jar'
    expected = {p.relative_to(source / 'target/classes').as_posix() for p in (source / 'target/classes').rglob('*') if p.is_file()}
    expected |= {'META-INF/MANIFEST.MF'} | {'META-INF/maven/io.github.pboachie.zrotext/' + JAVA_ID + '/' + n for n in ('pom.xml', 'pom.properties')}
    check_zip(source / 'target' / name, expected, 'META-INF/LICENSE', (source / 'LICENSE').read_bytes())
    destination = feed / 'io/github/pboachie/zrotext' / JAVA_ID / VERSION
    destination.mkdir(parents=True)
    shutil.copyfile(source / 'target' / name, destination / name)
    copy(source / 'pom.xml', destination / (JAVA_ID + '-' + VERSION + '.pom'))
    for file in list(destination.iterdir()):
        for algorithm in ('sha1', 'sha256'):
            write(file.with_name(file.name + '.' + algorithm), hashlib.new(algorithm, file.read_bytes()).hexdigest())
    consumer = stage / 'consumer'; consumer.mkdir()
    for suite, test in SUITES.items():
        directory = 'original-reply' if suite == 'original-protected' else 'http' if suite == 'current-http' else suite
        copy(HERE / 'java' / directory / (test + '.java'), consumer / 'src/main/java' / (test + '.java'))
    write(consumer / 'pom.xml', header.format('installed-consumer') + '<repositories><repository><id>candidate</id><url>' + feed.as_uri() + '</url></repository></repositories><dependencies>' + dependency.format('io.github.pboachie.zrotext', JAVA_ID, VERSION) + '</dependencies><build>' + plugins + '</build></project>')
    shutil.rmtree(source)
    run(mvn, '--batch-mode', '-Dmaven.repo.local=' + str(stage / 'consumer-cache'), 'compile', 'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies', cwd=consumer, env=env)
    installed = consumer / 'target/dependency' / name
    if installed.read_bytes() != (destination / name).read_bytes():
        raise ValueError('Maven resolved another candidate')
    dependencies = sorted((consumer / 'target/dependency').glob('*.jar'))
    if {p.name for p in dependencies} != {name, 'jna-5.17.0.jar', 'gson-2.14.0.jar', 'error_prone_annotations-2.48.0.jar'}:
        raise ValueError('Unexpected Java dependencies')
    jna_jar = consumer / 'target/dependency/jna-5.17.0.jar'
    if hashlib.sha256(jna_jar.read_bytes()).hexdigest() != 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0':
        raise ValueError('Resolved JNA checksum mismatch')
    for jar, expected_hash in (('gson-2.14.0.jar', '2cbd119bf1961c28788310963dc80ba65f58cdeec1dd139c8bdb1240faa2c36f'),
                               ('error_prone_annotations-2.48.0.jar', 'b49c5c958316ed67a09c699dda9aa749caf434d51d863dea599ef36a49b9c855')):
        if hashlib.sha256((consumer / 'target/dependency' / jar).read_bytes()).hexdigest() != expected_hash:
            raise ValueError('Resolved JSON dependency checksum mismatch')
    classpath = os.pathsep.join(map(str, [consumer / 'target/classes', *dependencies]))
    return {suite: [tool('java'), '-cp', classpath, 'org.zrotext.candidate.' + test] for suite, test in SUITES.items()}, env


def csharp(stage, source, feed, env):
    dotnet = tool('dotnet')
    for path in runtime_sources('csharp'):
        copy(path, source / path.name)
    config = stage / 'NuGet.Config'
    tree = ET.Element('configuration'); sources = ET.SubElement(tree, 'packageSources'); ET.SubElement(sources, 'clear')
    ET.SubElement(sources, 'add', key='candidate', value=str(feed)); ET.SubElement(sources, 'add', key='nuget', value='https://api.nuget.org/v3/index.json')
    mapping = ET.SubElement(tree, 'packageSourceMapping')
    ET.SubElement(ET.SubElement(mapping, 'packageSource', key='candidate'), 'package', pattern=CS_ID)
    ET.SubElement(ET.SubElement(mapping, 'packageSource', key='nuget'), 'package', pattern='Microsoft.*')
    ET.ElementTree(tree).write(config, encoding='utf-8', xml_declaration=True)
    properties = '<TargetFramework>net8.0</TargetFramework><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors>'
    write(source / 'Library.csproj', '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>' + properties + '<PackageId>' + CS_ID + '</PackageId><AssemblyName>' + CS_ID + '</AssemblyName><Version>' + VERSION + '</Version><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression><Description>Experimental native sealed companions</Description><PackageReadmeFile>README.md</PackageReadmeFile></PropertyGroup><ItemGroup><None Include="LICENSE" Pack="true" PackagePath=""/><None Include="README.md" Pack="true" PackagePath=""/></ItemGroup></Project>')
    env = dict(env, NUGET_PACKAGES=str(stage / 'build-cache'), DOTNET_CLI_HOME=str(stage / 'dotnet-home'), DOTNET_NOLOGO='1')
    run(dotnet, 'pack', source / 'Library.csproj', '-c', 'Release', '--output', feed, '--configfile', config, '-p:PathMap=' + str(stage) + '=/_/', cwd=stage, env=env)
    archive = feed / (CS_ID + '.' + VERSION + '.nupkg')
    with zipfile.ZipFile(archive) as packed:
        metadata = {n for n in packed.namelist() if n.startswith('package/services/metadata/core-properties/') and n.endswith('.psmdcp')}
    if len(metadata) != 1:
        raise ValueError('Unexpected NuGet metadata')
    check_zip(archive, metadata | {'_rels/.rels', '[Content_Types].xml', CS_ID + '.nuspec', 'lib/net8.0/' + CS_ID + '.dll', 'LICENSE', 'README.md'}, 'LICENSE', (source / 'LICENSE').read_bytes())
    for suite in SUITES:
        consumer = stage / 'consumer' / suite
        copy(HERE / 'csharp' / suite / 'Program.cs', consumer / 'Program.cs')
        write(consumer / 'Consumer.csproj', '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>' + properties + '<OutputType>Exe</OutputType><RollForward>Major</RollForward></PropertyGroup><ItemGroup><PackageReference Include="' + CS_ID + '" Version="' + VERSION + '"/></ItemGroup></Project>')
    shutil.rmtree(source)
    env['NUGET_PACKAGES'] = str(stage / 'consumer-cache')
    commands = {}
    for suite in SUITES:
        consumer = stage / 'consumer' / suite
        run(dotnet, 'restore', consumer / 'Consumer.csproj', '--configfile', config, cwd=consumer, env=env)
        run(dotnet, 'build', consumer / 'Consumer.csproj', '--no-restore', '-c', 'Release', '-o', consumer / 'installed', cwd=consumer, env=env)
        installed = Path(env['NUGET_PACKAGES']) / CS_ID.lower() / VERSION / (CS_ID.lower() + '.' + VERSION + '.nupkg')
        if installed.read_bytes() != archive.read_bytes():
            raise ValueError('NuGet resolved another candidate')
        commands[suite] = [dotnet, str(consumer / 'installed/Consumer.dll')]
    return commands, env


def ruby(stage, source, feed, env):
    executable = tool('ruby')
    entries = []
    for path in runtime_sources('ruby'):
        relative = path.relative_to(HERE.parent)
        destination = source / 'lib/zrotext_native_candidate' / relative
        copy(path, destination)
        entries.append('require_relative ' + repr('zrotext_native_candidate/' + relative.with_suffix('').as_posix()))
    write(source / 'lib/zrotext_native_candidate.rb', '# frozen_string_literal: true\n' + '\n'.join(entries) + '\n')
    files = sorted(p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file())
    write(source / 'native.gemspec', "Gem::Specification.new do |s|\ns.name='" + RUBY_ID + "'\ns.version='0.1.0.alpha.1'\ns.summary='Experimental ZROtext native sealed companions'\ns.authors=['ZROtext contributors']\ns.homepage='https://github.com/pboachie/zrotext'\ns.license='AGPL-3.0-only'\ns.required_ruby_version='>= 3.3'\ns.files=" + repr(files) + "\ns.require_paths=['lib']\nend\n")
    run(executable, '-rrubygems/gem_runner', '-e', 'Gem::GemRunner.new.run(ARGV)', '--', 'build', 'native.gemspec', cwd=source, env=env)
    archive = next(source.glob('*.gem')); shutil.copyfile(archive, feed / archive.name)
    with tarfile.open(archive) as gem:
        payload = gem.extractfile('data.tar.gz').read()
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as data:
        members = data.getmembers()
        if len(members) != len(files) or {m.name for m in members} != set(files):
            raise ValueError('Unexpected gem inventory')
        for member in members:
            if not member.isfile() or data.extractfile(member).read() != (source / member.name).read_bytes():
                raise ValueError('Gem payload differs from reviewed source')
    commands = {}
    for suite in SUITES:
        name = ('protected.rb' if suite == 'original-protected' else 'current_test.rb' if suite == 'current-http' else 'test.rb' if suite.endswith('journal') or suite in ('original-reply', 'original-history', 'http')
                else 'custody_test.rb' if suite == 'custody' else 'compose_test.rb')
        directory = 'original-reply' if suite == 'original-protected' else 'http' if suite == 'current-http' else suite
        text = (HERE / 'ruby' / directory / name).read_text(encoding='utf-8')
        text, count = re.subn(r"^require_relative '[^']+'$", "require 'zrotext_native_candidate'", text, flags=re.M)
        if not count:
            raise ValueError('Review changed Ruby consumer imports')
        consumer = stage / 'consumer' / suite / name
        # Check every loaded candidate module, including child-process restores.
        guard = "\nexpected=Gem.loaded_specs.fetch('zrotext-native-candidate').full_gem_path\n$LOADED_FEATURES.grep(/zrotext_native_candidate/).each { |f| raise 'outside installed gem' unless File.realpath(f).start_with?(File.realpath(expected)+File::SEPARATOR) }\n"
        text = text.replace("require 'zrotext_native_candidate'", "require 'zrotext_native_candidate'" + guard, 1)
        write(consumer, text)
        commands[suite] = [executable, str(consumer)]
    shutil.rmtree(source)
    env = dict(env, GEM_HOME=str(stage / 'gems'), GEM_PATH=str(stage / 'gems'))
    run(executable, '-rrubygems/gem_runner', '-e', 'Gem::GemRunner.new.run(ARGV)', '--', 'install', '--local', '--no-document', feed / archive.name, cwd=stage, env=env)
    shim = stage / 'injection'
    write(shim / 'zrotext_native_candidate.rb', "gem 'zrotext-native-candidate'\nrequire File.join(Gem.loaded_specs.fetch('zrotext-native-candidate').full_gem_path,'lib/zrotext_native_candidate.rb')\n")
    rejected = subprocess.run(commands['root-journal'], input='', capture_output=True, text=True,
                              cwd=stage, env=dict(env, RUBYLIB=str(shim)), timeout=15)
    if rejected.returncode == 0 or 'outside installed gem' not in rejected.stderr:
        raise ValueError('Installed Ruby source injection was not rejected')
    return commands, env


def acceptance(args, stage, commands, env):
    for name, pin in PINS.items():
        path = getattr(args, name)
        if run('git', '-C', path, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != pin:
            raise ValueError('Unexpected independent producer: ' + name)
        run('git', '-C', path, 'diff', '--quiet', 'HEAD', '--')
    command_files = {}
    for suite, command in commands.items():
        command_files[suite] = stage / (suite + '.json')
        write(command_files[suite], json.dumps(command))
    run(sys.executable, HERE / 'root-journal-run.py', '--language', args.target, '--producer', args.root_producer, '--controls', args.root_controls, '--command-file', command_files['root-journal'], cwd=stage, env=env)
    run(sys.executable, HERE / 'election-journal-run.py', '--language', args.target, '--producer', args.producer03, '--command-file', command_files['election-journal'], cwd=stage, env=env)
    if args.target == 'java':
        run(sys.executable, HERE / 'java/custody/run.py', '--producer', args.custody_producer, '--command-file', command_files['custody'], cwd=stage, env=env)
        run(sys.executable, HERE / 'java/composition/run.py', '--producer', args.producer03, '--command-file', command_files['composition'], cwd=stage, env=env)
    else:
        for suite, producer in [('custody', args.custody_producer), ('composition', args.producer03)]:
            receipt = Path(tempfile.gettempdir()) / (stage.name + '-' + suite + '-pending.txt')
            run(*commands[suite], producer / 'sdk/native/sealed-candidate/python', receipt, cwd=stage, env=env, timeout=180)
            if receipt.exists():
                raise ValueError('Preserve pending native cleanup receipt: ' + str(receipt))
    run(sys.executable, HERE / 'composition02-run.py', '--language', args.target, '--producer', args.producer02, '--controls', args.controls, '--command-file', command_files['composition02'], cwd=stage, env=env)
    original_commands = stage / 'original-installed.json'
    write(original_commands, json.dumps({'software': commands['original-reply'], 'protected': commands['original-protected']}))
    run(sys.executable, HERE / 'original-reply-run.py', '--language', args.target,
        '--producer', args.original_producer, '--command-file', original_commands, cwd=stage, env=env)

    run(sys.executable, HERE / 'original-history-run.py', '--language', args.target,
        '--producer', args.original_producer, '--command-file', command_files['original-history'], cwd=stage, env=env)
    run(sys.executable, HERE / 'original-http-run.py', '--language', args.target,
        '--fixture', args.http_fixture, '--command-file', command_files['http'], cwd=stage, env=env)
    run(sys.executable, HERE / 'original-current-run.py', '--language', args.target,
        '--fixture', args.current_fixture, '--producer', args.original_producer,
        '--command-file', command_files['current-http'], cwd=stage, env=env)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    for name in PINS:
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    for name in PINS:
        setattr(args, name, getattr(args, name).resolve())
    output = args.out.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError('Use a new external artifact directory')
    with tempfile.TemporaryDirectory(prefix='zrotext-native-packages-') as directory:
        stage = Path(directory); source = stage / 'source'; feed = stage / 'feed'; feed.mkdir()
        copy(ROOT / 'LICENSE', source / 'LICENSE')
        copy(HERE / 'packages.md', source / 'README.md')
        commands, env = globals()[args.target](stage, source, feed, env_clean())
        if source.exists():
            raise ValueError('Source staging was not removed')
        acceptance(args, stage, commands, env)
        shutil.copytree(feed, output)
    report = {'target': args.target, 'scope': 'Installed candidate consumers; native qualification requires QUALIFIED output; no publication or full SDK parity',
              'sha256': {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in output.rglob('*') if p.is_file()}}
    write(output / 'manifest.json', json.dumps(report, indent=2) + '\n')
    print(args.target + ' native candidate archive and installed consumers passed')


if __name__ == '__main__':
    main()
