"""Diagnostic probe for upstream Tungsten #65; does not qualify redirect safety."""
import json
from test_wire import Wire

probe = Wire()
probe.setUp()
try:
    probe.reply = (302, {"Location": "/redirected"}, {})
    outcome = probe.invoke()
    print(json.dumps({"upstream_issue": "https://github.com/pboachie/tungsten/issues/65",
                      "same_origin_read_requests": len(probe.calls),
                      "paths": [call[1] for call in probe.calls],
                      "outcome": outcome,
                      "redirect_safety_qualified": False}))
finally:
    probe.tearDown()
