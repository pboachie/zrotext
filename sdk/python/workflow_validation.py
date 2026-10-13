"""Compatibility import for existing source-checkout contract consumers."""
import sys
from workflow.zrotext_workflow import validation
sys.modules[__name__] = validation
