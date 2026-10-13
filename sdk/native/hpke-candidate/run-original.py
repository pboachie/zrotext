"""Maintained selected role3 ciphertext and conditional native PCP acceptance."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
REVISION = "72124e1a3ff28e782f870eeddbdc33cacf8ca3b4"


def run(*args, **kwargs):
    return subprocess.run(list(map(str,args)),check=True,**kwargs)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer",type=Path,required=True)
    parser.add_argument("--language",choices=("rust","go"),required=True)
    args=parser.parse_args();producer=args.producer.resolve()
    if run("git","-C",producer,"rev-parse","HEAD",capture_output=True,text=True).stdout.strip()!=REVISION:
        raise ValueError("Unexpected producer revision")
    run("git","-C",producer,"diff","--quiet","HEAD","--")
    env={k:v for k,v in os.environ.items() if k not in ("NODE_OPTIONS","NODE_PATH")}
    fixture=run("node",producer/"sdk/native/sealed-candidate/python/produce-selected-reply02.mjs",capture_output=True,text=True,env=env).stdout
    with tempfile.TemporaryDirectory(prefix="zrotext-native-original-") as directory:
        target=Path(directory);suffix=".exe" if os.name=="nt" else ""
        names=["original"]+(["cng"] if os.name=="nt" else [])
        for name in names:
            if args.language=="go":
                run("go","build","-o",target/(name+suffix),"./cmd/"+name,cwd=ROOT/"go")
            else:
                run("cargo","build","--locked","--example",name,"--target-dir",target,cwd=ROOT/"rust")
        binary=target/("original"+suffix) if args.language=="go" else target/"debug/examples"/("original"+suffix)
        run(binary,input=fixture,text=True,timeout=60)
        if os.name=="nt":
            spec=importlib.util.spec_from_file_location("native_cng",ROOT/"run-cng.py")
            native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
            binary=target/"cng.exe" if args.language=="go" else target/"debug/examples/cng.exe"
            native.exercise(binary,producer,original=True)


if __name__=="__main__":
    main()
