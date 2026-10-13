"""Compatibility import for existing source-checkout workflow consumers."""
import sys
from workflow.zrotext_workflow import client
sys.modules[__name__] = client
