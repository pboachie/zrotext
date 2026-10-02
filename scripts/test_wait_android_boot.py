# SPDX-License-Identifier: AGPL-3.0-only
import subprocess
import unittest
import wait_android_boot as boot


class BootReadinessTests(unittest.TestCase):
    def run_wait(self, query, budget=10, alive=lambda: True):
        now = [0]
        self.now = now
        def sleep(seconds):
            now[0] += seconds
        return boot.wait_for_boot(1, query, budget=budget,
                                  clock=lambda: now[0], sleep=sleep, alive=alive)

    def test_requires_explicit_boot_completion(self):
        values = iter(["", "0", "unexpected", "1\r\n"])
        result = self.run_wait(lambda _: next(values))
        self.assertEqual("ready", result["result"])
        self.assertEqual(4, result["probes"])

    def test_deadline_does_not_accept_missing_completion(self):
        result = self.run_wait(lambda _: "", budget=3)
        self.assertEqual("deadline", result["result"])
        self.assertEqual(3, result["elapsed_seconds"])

    def test_process_exit_stops_before_query(self):
        result = self.run_wait(lambda _: self.fail("Unexpected query"), alive=lambda: False)
        self.assertEqual("process-exited", result["result"])
        self.assertEqual(0, result["probes"])

    def test_query_timeout_is_bounded_by_remaining_budget(self):
        timeouts = []
        def query(timeout):
            timeouts.append(timeout)
            self.now[0] += timeout
            raise subprocess.TimeoutExpired("synthetic", timeout)
        result = self.run_wait(query, budget=7)
        self.assertEqual([5, 1], timeouts)
        self.assertEqual("deadline", result["result"])

    def test_late_completion_is_rejected(self):
        def query(timeout):
            self.now[0] += timeout
            return "1"
        self.assertEqual("deadline", self.run_wait(query, budget=2)["result"])

    def test_process_dying_during_successful_query_is_rejected(self):
        running = [True]
        def query(_):
            running[0] = False
            return "1"
        result = self.run_wait(query, alive=lambda: running[0])
        self.assertEqual("process-exited", result["result"])

    def test_query_error_does_not_expose_raw_output(self):
        def query(_):
            raise subprocess.CalledProcessError(1, "synthetic", output="private fixture")
        result = self.run_wait(query, budget=1)
        self.assertEqual("query-failed", result["last_probe"])
        self.assertNotIn("private", str(result))

    def test_invalid_budget_is_rejected(self):
        for budget in (0, 301):
            with self.assertRaises(ValueError):
                self.run_wait(lambda _: "1", budget=budget)
