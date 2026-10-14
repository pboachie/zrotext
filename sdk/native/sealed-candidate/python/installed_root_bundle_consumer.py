"""External consumer; executed with -I against installed public package."""
import json
from pathlib import Path
import sys
import zrotext_native_candidate as package
from zrotext_native_candidate import verify_published_root_bundle,RootBundleError


def exercise(cases):
    assert len(cases)==41
    outcomes=[]
    for case in cases:
        pin=bytes.fromhex(case['pin']);fingerprint=bytes.fromhex(case['fingerprint'])
        published={key:bytes.fromhex(value) for key,value in case['published'].items()}
        try:result=verify_published_root_bundle(pin,fingerprint,case['origin'],published)
        except RootBundleError:accepted=False
        else:
            accepted=True
            assert result.root_pin==pin and result.encrypted_backup==published['encryptedBackup'] and result.public_card==published['publicCard']
            assert not hasattr(result,'private_key')
        assert accepted==case['accept'],case['name']
        outcomes.append(accepted)
    assert sum(outcomes)==3
    return len(outcomes)


if __name__=='__main__':
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    print(json.dumps(dict(installed=True,public_root_bundle_cases=exercise(json.load(sys.stdin)['cases']))))
