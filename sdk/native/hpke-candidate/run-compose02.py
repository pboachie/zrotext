"""Native protected composition with pinned maintained TypeScript verification.

Capability absence is unqualified; every failure after creation fails the gate.
Only disposable public points/ciphertext cross processes. Pending key receipts stay private.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parent
REVISION = "a13ea1e3d6f6db594485c19b36c43fe642e67c7a"

def run(*args, **kwargs):
    return subprocess.run(list(map(str,args)),check=True,**kwargs)

def exercise(binary, producer):
    probe=subprocess.run([str(binary),"--probe"],capture_output=True,timeout=30)
    if probe.returncode==77:
        print("Native signing capability unavailable; protected composition NOT qualified")
        return False
    if probe.returncode:
        raise RuntimeError("Native signing probe failed")
    process=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    ready=queue.Queue()
    threading.Thread(target=lambda:ready.put(process.stdout.readline()),daemon=True).start()
    try:
        first=json.loads(ready.get(timeout=45))
        if set(first)!={"public"} or len(first["public"])!=130:
            raise ValueError("Expected native public signer point")
        env={k:v for k,v in os.environ.items() if k not in ("NODE_PATH","NODE_OPTIONS")}
        fixture=run(shutil.which("node"),producer/"sdk/native/sealed-candidate/python/produce-fixture.mjs","--signer-point",first["public"],capture_output=True,text=True,timeout=45,env=env).stdout
        fixture=run(shutil.which("node"),ROOT/"root-controls.mjs",producer,input=fixture,capture_output=True,text=True,timeout=45,env=env).stdout
        output,errors=process.communicate(fixture,timeout=90)
        if process.returncode:
            raise RuntimeError("Native protected composition failed: "+errors)
        result=json.loads(output)
        for envelope in [result["envelope"],*result["boundaries"]]:
            payload=json.dumps({"fixture":json.loads(fixture),"envelope":envelope,"expectedText":result["expectedText"]})
            independent=run(shutil.which("node"),producer/"sdk/native/sealed-candidate/python/consume-native02.mjs",input=payload,capture_output=True,text=True,timeout=45,env=env)
            if json.loads(independent.stdout)!={"verified":True,"openedRecipients":2}:
                raise ValueError("Independent native ciphertext consumer refused")
        payload=json.dumps({"fixture":json.loads(fixture),"envelope":result["rotatedEnvelope"],"expectedText":result["expectedText"]})
        independent=run(shutil.which("node"),ROOT/"consume-rotated02.mjs",producer,input=payload,capture_output=True,text=True,timeout=45,env=env)
        if json.loads(independent.stdout)!={"verified":True,"openedRecipients":2}:
            raise ValueError("Independent rotated ciphertext consumer refused")
        print("Native protected composition, durable replay controls and independent TypeScript two-recipient opening passed")
        return True
    finally:
        if process.poll() is None:
            try:
                process.communicate("",timeout=45)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
                raise RuntimeError("Cleanup timed out; retain private pending receipt for exact owned recovery")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer",type=Path,required=True)
    parser.add_argument("--language",choices=("rust","go"),required=True)
    args=parser.parse_args()
    if os.name!="nt":
        raise SystemExit("Windows native custody required; no protected acceptance")
    producer=args.producer.resolve()
    revision=run("git","-C",producer,"rev-parse","HEAD",capture_output=True,text=True).stdout.strip()
    if revision!=REVISION:
        raise ValueError("Unexpected producer revision")
    run("git","-C",producer,"diff","--quiet","HEAD","--")
    with tempfile.TemporaryDirectory(prefix="zrotext-native-compose-build-") as directory:
        target=Path(directory)
        if args.language=="go":
            binary=target/"compose.exe"
            run("go","build","-o",binary,"./cmd/compose02",cwd=ROOT/"go")
        else:
            run("cargo","build","--locked","--example","compose02","--target-dir",target,cwd=ROOT/"rust")
            binary=target/"debug/examples/compose02.exe"
        exercise(binary,producer)

if __name__=="__main__":
    main()
