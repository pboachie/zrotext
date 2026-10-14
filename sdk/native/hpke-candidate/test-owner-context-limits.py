"""Public installed owner-context deadline, close and retained-admission checks."""
import argparse
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
result = subprocess.run([args.binary, '--limits'], capture_output=True, text=True,
                        timeout=35, check=True)
assert json.loads(result.stdout) == {'installed_owner_context_limits': 11}
print('Eleven installed owner-context closure, deadline and retained-admission controls passed')
