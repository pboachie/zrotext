"""Pinned maintained ZTWT01 interop; synthetic keys only, no network services."""
import argparse
import base64
import concurrent.futures
import copy
import json
import pathlib
import subprocess

PIN = "26e876da9f34372d9cf26511993cf633971e0037"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--producer", type=pathlib.Path, required=True)
    command = p.add_mutually_exclusive_group(required=True)
    command.add_argument("--binary")
    command.add_argument("--command-file", type=pathlib.Path)
    p.add_argument("--hardware", action="store_true")
    p.add_argument("--fail-setup", action="store_true", help="exercise owned-child EOF cleanup after public-point handshake")
    args = p.parse_args()
    source = args.producer.resolve()
    assert subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() == PIN
    assert not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip()
    producer = source / "sdk/native/sealed-candidate/python/template-interop.mjs"
    argv = [args.binary] if args.binary else json.loads(args.command_file.read_text(encoding="utf-8"))
    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or not v or "\0" in v for v in argv):
        raise ValueError("trusted command must be a nonempty JSON string array without NUL")
    if args.fail_setup and not args.hardware:
        p.error("--fail-setup requires --hardware")
    process = subprocess.Popen(argv + (["--hardware"] if args.hardware else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        extra = []
        if args.hardware:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(process.stdout.readline)
                try:
                    point = json.loads(future.result(timeout=60))["public"]
                except BaseException:
                    process.stdin.close()
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                    raise
            assert len(bytes.fromhex(point)) == 65
            extra = ["--recipient-point", point]
            if args.fail_setup:
                out, _ = process.communicate("", timeout=30)
                assert process.returncode != 0
                assert json.loads(out.splitlines()[-1]) == {"owned_key_deleted": True}
                print("owned child setup-failure EOF cleanup passed")
                return
        fixture = json.loads(subprocess.check_output(["node", str(producer), *extra], text=True, encoding="utf-8", timeout=90))
        assert ("archiveScalar" not in fixture) == args.hardware
        cases, expected = [], []

        def add(accepted, *, mode="open", envelope=None, scope=None, clock=None, fail=False, canonical=None):
            cases.append({"Mode": mode, "Envelope": envelope or fixture["envelope"], "Scope": scope or fixture["scope"], "Clock": clock or [10000, 10000], "FailFinal": fail, "Canonical": canonical or fixture["canonical"]})
            expected.append(accepted)

        add(True)
        add(True, mode="seal")
        add(True, mode="seal")
        for mode in ["open", "seal"]:
            add(False, mode=mode, fail=True)
            add(False, mode=mode, clock=[10001, 10000])
            add(False, mode=mode, clock=[10000, 20000])
            add(False, mode=mode, clock=[9999])
            for field in fixture["scope"]:
                changed = copy.deepcopy(fixture["scope"])
                if isinstance(changed[field], str):
                    raw = bytearray(base64.b64decode(changed[field])); raw[0] ^= 1
                    changed[field] = base64.b64encode(raw).decode()
                    # Seal may create a fresh template/interval/peer context. These
                    # fields are external context, not manifest authority.
                    if mode == "seal" and field in {"intervalId", "templateId", "peerDigest"}:
                        continue
                else:
                    changed[field] = 0
                add(False, mode=mode, scope=changed)
        add(False, envelope=fixture["malformed"])
        add(False, envelope=fixture["invalidUtf8"])
        wire = base64.b64decode(fixture["envelope"])
        positions = range(len(wire)) if not args.hardware else [0, 221, 222, 286, 287, 290, 291, len(wire)-1]
        for at in positions:
            bad = bytearray(wire); bad[at] ^= 1
            add(False, envelope=base64.b64encode(bad).decode())
        for bad in [wire[:-1], wire + b"\0", bytes(307), bytes(33076)]:
            add(False, envelope=base64.b64encode(bad).decode())
        large = {"v": 1, "template": "\x01" * 4096, "values": {"x": "\x01" * 512, "y": "\x01" * 512, "z": "\x01" * 512}}
        canonical = json.dumps(large, separators=(",", ":"), ensure_ascii=False).encode()
        assert len(canonical) > 32768
        add(False, mode="seal", canonical=base64.b64encode(canonical).decode())
        out, err = process.communicate(json.dumps({"Fixture": fixture, "Cases": cases}), timeout=180)
        assert process.returncode == 0, "native probe failed: " + err
        lines = out.splitlines()
        result = json.loads(lines[0])["cases"]
        assert len(result) == len(expected)
        for i, (actual, accept) in enumerate(zip(result, expected)):
            assert actual["accepted"] == accept, (i, cases[i]["Mode"], actual, accept)
            if accept and cases[i]["Mode"] == "open":
                assert actual["canonical"] == fixture["canonical"]
            if accept:
                assert actual["calls"] == 2
        assert result[1]["envelope"] != result[2]["envelope"], "ephemeral key reused"
        if args.hardware:
            assert json.loads(lines[-1]) == {"owned_key_deleted": True}
        else:
            for i in [1, 2]:
                consumed = subprocess.check_output(["node", str(producer), "--consume"], input=json.dumps({"fixture": fixture, "envelope": result[i]["envelope"], "expectedCanonical": fixture["canonical"]}), text=True, encoding="utf-8", timeout=60)
                assert json.loads(consumed)["verified"] is True
        print(f"{len(cases)} native template controls passed; protected={args.hardware}; reverse interop={not args.hardware}")
    finally:
        if process.poll() is None:
            if not process.stdin.closed:
                process.stdin.close()
            process.stdin = None
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.communicate(timeout=10)
                raise AssertionError("unresponsive native child; private ownership receipt retained")


if __name__ == "__main__":
    main()
