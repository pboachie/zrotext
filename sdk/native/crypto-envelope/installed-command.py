"""Validate a trusted local test driver's explicit argument vector; never use a shell."""
import json


def load(path):
    value = json.loads(path.read_text(encoding='utf-8'))
    if (type(value) is not list or not value or
            any(type(arg) is not str or not arg or '\0' in arg for arg in value)):
        raise ValueError('Expected a nonempty installed command argument list')
    return value
