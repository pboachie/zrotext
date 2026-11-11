# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic receipts exercise every fail-closed execution evidence boundary."""

import copy
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import ksp_execution_trace as trace


def record(event, task, **fields):
    return {"event": event, "task": task, **fields}


def records(reused=False, all_active=False):
    active = trace.TASKS if all_active else trace.REQUIRED_ACTIVE
    result = []
    if not reused:
        result.extend(record("config", task, processors=1 if task in active else 0, gated=True)
                      for task in sorted(trace.TASKS))
    for index, task in enumerate(sorted(active)):
        result.extend((record("start", task, nano=index * 20 + 1),
                       record("end", task, nano=index * 20 + 11)))
    return result


def log(reused=False, entries=None, all_active=False, outcomes=None):
    active = trace.TASKS if all_active else trace.REQUIRED_ACTIVE
    if entries is None:
        entries = records(reused, all_active)
    if outcomes is None:
        outcomes = {task: "" if task in active else " SKIPPED" for task in trace.TASKS}
    lines = [trace.PREFIX + json.dumps(item) for item in entries]
    lines.extend("> Task " + task + outcome for task, outcome in sorted(outcomes.items()))
    lines.extend(("BUILD SUCCESSFUL in 3s", "Configuration cache entry " +
                  ("reused." if reused else "stored.")))
    return "\n".join(lines) + "\n"


class KspExecutionTraceTests(unittest.TestCase):
    def test_cold_and_reused_cache_require_both_real_variants(self):
        self.assertEqual(trace.verify(log(), log(True)), trace.REQUIRED_ACTIVE)

    def test_all_four_processing_tasks_must_be_serialized_if_configured(self):
        self.assertEqual(trace.verify(log(all_active=True), log(True, all_active=True)), trace.TASKS)

    def test_monotonic_origin_may_be_negative(self):
        cold, warm = records(), records(True)
        for item in cold + warm:
            if "nano" in item:
                item["nano"] -= 100
        self.assertEqual(trace.verify(log(entries=cold), log(True, warm)), trace.REQUIRED_ACTIVE)

    def test_missing_or_duplicate_configuration_fails(self):
        original = records()
        for changed in (original[1:], original + original[:1]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                trace.verify(log(entries=changed), log(True))

    def test_ungated_or_unexpected_configuration_fails(self):
        for fields in ({"gated": False}, {"gated": 1}, {"processors": -1},
                       {"processors": True}, {"processors": "1"},
                       {"task": ":app:kspFutureKotlin"}, {"extra": "field"}):
            changed = records()
            changed[0].update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                trace.verify(log(entries=changed), log(True))

    def test_required_release_processing_cannot_be_disabled(self):
        changed = records()
        for item in changed:
            if item["event"] == "config" and item["task"] == ":app:kspReleaseKotlin":
                item["processors"] = 0
        with self.assertRaisesRegex(ValueError, "Debug and release"):
            trace.verify(log(entries=changed), log(True))

    def test_missing_duplicate_unknown_or_partial_interval_fails(self):
        original = records(True)
        variants = [original[1:], original + original[:1], original[:-2]]
        changed = copy.deepcopy(original)
        changed[0]["task"] = ":app:kspFutureKotlin"
        variants.append(changed)
        changed = copy.deepcopy(original)
        changed[0]["event"] = "finished"
        variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                trace.verify(log(), log(True, changed))

    def test_executed_zero_processor_task_requires_complete_interval(self):
        outcomes = {task: "" if task in trace.REQUIRED_ACTIVE else " SKIPPED" for task in trace.TASKS}
        outcomes[":app:kspDebugUnitTestKotlin"] = ""
        changed = records(True)
        changed.extend((record("start", ":app:kspDebugUnitTestKotlin", nano=50),
                        record("end", ":app:kspDebugUnitTestKotlin", nano=60)))
        self.assertEqual(trace.verify(log(), log(True, changed, outcomes=outcomes)), trace.REQUIRED_ACTIVE)
        for incomplete in (changed[:-1], changed[:-2], changed + changed[-1:]):
            with self.subTest(incomplete=incomplete), self.assertRaises(ValueError):
                trace.verify(log(), log(True, incomplete, outcomes=outcomes))

    def test_zero_processor_noops_are_accounted_for_in_both_passes(self):
        outcomes = {task: "" for task in trace.TASKS}
        passes = []
        for reused in (False, True):
            changed = records(reused)
            changed.extend((record("start", ":app:kspDebugUnitTestKotlin", nano=50),
                            record("end", ":app:kspDebugUnitTestKotlin", nano=60),
                            record("start", ":app:kspDebugAndroidTestKotlin", nano=70),
                            record("end", ":app:kspDebugAndroidTestKotlin", nano=80)))
            passes.append(log(reused, changed, outcomes=outcomes) +
                          "> Task :app:kspDebugKotlin\n> Task :app:kspReleaseKotlin\n")
        self.assertEqual(trace.verify(*passes), trace.REQUIRED_ACTIVE)

    def test_skipped_zero_processor_task_must_not_emit_execution_receipt(self):
        changed = records(True)
        changed.extend((record("start", ":app:kspDebugUnitTestKotlin", nano=50),
                        record("end", ":app:kspDebugUnitTestKotlin", nano=60)))
        with self.assertRaisesRegex(ValueError, "Skipped task has execution receipts"):
            trace.verify(log(), log(True, changed))

    def test_zero_processor_intervals_cannot_overlap_any_executed_task(self):
        outcomes = {task: "" for task in trace.TASKS}
        for start, end in ((5, 15), (45, 65)):
            changed = records(True)
            changed.extend((record("start", ":app:kspDebugUnitTestKotlin", nano=start),
                            record("end", ":app:kspDebugUnitTestKotlin", nano=end),
                            record("start", ":app:kspDebugAndroidTestKotlin", nano=50),
                            record("end", ":app:kspDebugAndroidTestKotlin", nano=60)))
            with self.subTest(start=start), self.assertRaisesRegex(ValueError, "Concurrent KSP"):
                trace.verify(log(), log(True, changed, outcomes=outcomes))

    def test_inverted_empty_invalid_or_overlapping_intervals_fail(self):
        original = records(True)
        mutations = [(1, "nano", 0), (1, "nano", 1), (0, "nano", True),
                     (0, "nano", "1"), (0, "nano", 2**63),
                     (0, "nano", -(2**63) - 1), (2, "nano", 5)]
        for index, key, value in mutations:
            changed = copy.deepcopy(original)
            changed[index][key] = value
            with self.subTest(value=value, index=index), self.assertRaises(ValueError):
                trace.verify(log(), log(True, changed))

    def test_interleaved_log_delivery_uses_worker_times_not_log_line_order(self):
        shuffled = list(reversed(records(True)))
        self.assertEqual(trace.verify(log(), log(True, shuffled)), trace.REQUIRED_ACTIVE)

    def test_every_active_task_requires_fresh_successful_outcome(self):
        original = {task: "" if task in trace.REQUIRED_ACTIVE else " SKIPPED" for task in trace.TASKS}
        for suffix in (" UP-TO-DATE", " FROM-CACHE", " SKIPPED", " NO-SOURCE", " FAILED", " UNKNOWN"):
            changed = dict(original, **{":app:kspDebugKotlin": suffix})
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                trace.verify(log(), log(True, outcomes=changed))

    def test_repeated_identical_plain_console_headers_are_not_duplicate_work(self):
        cold = log() + "> Task :app:kspDebugKotlin\n> Task :app:kspReleaseKotlin\n"
        warm = log(True) + "> Task :app:kspDebugKotlin\n> Task :app:kspDebugUnitTestKotlin SKIPPED\n"
        self.assertEqual(trace.verify(cold, warm), trace.REQUIRED_ACTIVE)
        # Headers may repeat, but a second start or end is still rejected.
        for item in records(True)[:2]:
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, "Duplicate task interval"):
                trace.verify(cold, warm + trace.PREFIX + json.dumps(item) + "\n")

    def test_missing_conflicting_or_unrecognized_task_outcome_fails(self):
        for changed in (log(True).replace("> Task :app:kspDebugKotlin\n", ""),
                        log(True) + "> Task :app:kspDebugKotlin UP-TO-DATE\n",
                        log(True) + "> Task :app:kspDebugUnitTestKotlin\n",
                        log(True) + "> Task :app:kspFutureKotlin\n",
                        log(True).replace("> Task :app:kspDebugKotlin", "> Task :app:kspDebugKotlin ???")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                trace.verify(log(), changed)

    def test_empty_processor_skip_requires_explicit_supported_outcome(self):
        self.assertEqual(trace.verify(log(), log(True).replace(" SKIPPED", " NO-SOURCE")),
                         trace.REQUIRED_ACTIVE)
        with self.assertRaisesRegex(ValueError, "did not execute fresh work"):
            trace.verify(log(), log(True).replace(" SKIPPED", " UP-TO-DATE"))

    def test_cache_receipts_and_single_success_are_mandatory(self):
        for changed in (log(True).replace("reused.", "stored."),
                        log(True).replace("Configuration cache entry reused.\n", ""),
                        log(True) + "Configuration cache entry reused.\n",
                        log(True) + "Configuration cache entry stored.\n",
                        log(True).replace("BUILD SUCCESSFUL in 3s", "BUILD FAILED in 3s"),
                        log(True) + "BUILD SUCCESSFUL in 4s\n"):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                trace.verify(log(), changed)
        with self.assertRaises(ValueError):
            trace.verify(log().replace("stored.", "reused."), log(True))

    def test_reconfiguration_during_warm_pass_fails(self):
        with self.assertRaisesRegex(ValueError, "Configuration ran"):
            trace.verify(log(), log(True, records()))

    def test_malformed_duplicate_fields_and_nonobject_json_fail(self):
        for value in ("[", "[]", "null", '{"event":"start","event":"end"}',
                      '{"event":"start","task":null,"nano":1}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.verify(log(), log(True) + trace.PREFIX + value + "\n")
        with self.assertRaises(ValueError):
            trace.verify(log(), log(True) + trace.PREFIX.rstrip() + "{}\n")

    def test_missing_or_oversized_log_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, RUNNER_TEMP=str(Path(directory).resolve())):
                folder = Path(directory) / trace.LOG_DIRECTORY
                folder.mkdir()
                path = folder / "cold.log"
                with self.assertRaises(ValueError):
                    trace.read_log("cold")
                path.write_text(log(), encoding="utf-8")
                self.assertEqual(trace.read_log("cold"), log())
                with path.open("wb") as stream:
                    stream.truncate(trace.MAX_LOG_BYTES + 1)
                with self.assertRaises(ValueError):
                    trace.read_log("cold")


if __name__ == "__main__":
    unittest.main()
