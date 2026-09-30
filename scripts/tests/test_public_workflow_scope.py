"""Keep public workflow credentials and build outputs explicitly scoped."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]

class PublicWorkflowScopeTests(unittest.TestCase):
    def test_checkout_never_persists_credentials(self):
        count = 0
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            text = path.read_text(encoding='utf-8')
            for step in re.split(r'^      - ', text, flags=re.MULTILINE):
                if 'uses: actions/checkout@' in step or step.startswith('uses: actions/checkout@'):
                    with self.subTest(workflow=path.name):
                        self.assertRegex(step, r'(?m)^          persist-credentials: false$')
                        count += 1
        self.assertGreater(count, 0)

    def test_docker_build_records_are_disabled_for_every_build(self):
        count = 0
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            text = path.read_text(encoding='utf-8')
            if 'uses: docker/build-push-action@' in text:
                with self.subTest(workflow=path.name):
                    self.assertRegex(text, r"(?m)^env:\n  DOCKER_BUILD_RECORD_UPLOAD: 'false'$")
                    # A narrower env must not override the workflow policy.
                    self.assertEqual(text.count('DOCKER_BUILD_RECORD_UPLOAD:'), 1)
                    count += 1
        self.assertGreater(count, 0)
