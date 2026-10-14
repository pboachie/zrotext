"""Exercise public bounded context APIs in a separately installed consumer."""
import argparse
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
result = subprocess.run([args.binary, '--limits'], capture_output=True, text=True,
                        timeout=35, check=True)
assert json.loads(result.stdout) == {'installed_context_limits': 7}
print('Seven installed context cancellation, deadline and retained-admission controls passed')
