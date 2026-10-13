"""Retained source imports cannot be shadowed by an unrelated workflow package."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class WorkflowSourceImports(unittest.TestCase):
    def test_local_namespace_wins_over_later_regular_workflow_package(self):
        source=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            collision=Path(directory)/'workflow';collision.mkdir()
            (collision/'__init__.py').write_text("raise RuntimeError('unrelated installed workflow package')\n")
            script='''import sys
sys.path.insert(0,sys.argv[1]);sys.path.append(sys.argv[2])
import workflow_client,workflow_validation
from workflow.zrotext_workflow import client,validation
assert workflow_client is client and workflow_validation is validation
assert workflow_client.WorkflowClient is client.WorkflowClient
assert len(workflow_client.workflow_functions())==8
'''
            subprocess.run([sys.executable,'-I','-c',script,str(source),directory],check=True,capture_output=True,text=True)


if __name__=='__main__':unittest.main()
