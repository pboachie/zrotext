"""Keep the device-compatibility matrix valid and its validator strict."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_device_compatibility as cdc  # noqa: E402


def find_run(data, run_id):
    return next(r for r in data["repeatable_runs"] if r["id"] == run_id)


class DeviceCompatibilityMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(cdc.DEFAULT_MATRIX.read_text(encoding="utf-8"))
        cls.doc = cdc.DEFAULT_DOC.read_text(encoding="utf-8")
        cls.min_sdk, cls.target_sdk = cdc.parse_sdk_bounds(
            cdc.DEFAULT_GRADLE.read_text(encoding="utf-8")
        )

    def check(self, matrix=None, doc=None):
        return cdc.validate(
            self.matrix if matrix is None else matrix,
            repo_root=cdc.ROOT,
            min_sdk=self.min_sdk,
            target_sdk=self.target_sdk,
            doc_text=self.doc if doc is None else doc,
        )

    def mutated(self, mutate):
        data = copy.deepcopy(self.matrix)
        mutate(data)
        return data

    def device(self, device_id):
        return next(d for d in self.matrix["devices"] if d["id"] == device_id)

    def test_committed_matrix_is_valid(self):
        self.assertEqual(self.check(), [])

    def test_cli_accepts_the_committed_files(self):
        self.assertEqual(cdc.main([]), 0)

    def test_declared_enums_match_the_validator(self):
        self.assertEqual(self.matrix["statuses"], list(cdc.STATUSES))
        self.assertEqual(self.matrix["sim_types"], list(cdc.SIM_TYPES))
        self.assertEqual(self.matrix["evidence_levels"], list(cdc.EVIDENCE_LEVELS))

    def test_gradle_bounds_parse_as_an_ordered_pair(self):
        self.assertLessEqual(self.min_sdk, self.target_sdk)

    def test_parse_sdk_bounds_requires_exactly_one_assignment_each(self):
        text = "defaultConfig {\n    minSdk = 28\n    targetSdk = 36\n}\n"
        self.assertEqual(cdc.parse_sdk_bounds(text), (28, 36))
        with self.assertRaises(ValueError):
            cdc.parse_sdk_bounds("minSdk = 28\n")
        with self.assertRaises(ValueError):
            cdc.parse_sdk_bounds("minSdk = 28\nminSdk = 29\ntargetSdk = 36\n")

    def test_physical_table_names_are_physical_matrix_entries(self):
        names = cdc.physical_table_devices(self.doc)
        self.assertTrue(names)
        physical = {d["name"] for d in self.matrix["devices"] if d["evidence"] == "physical"}
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, physical)

    def test_rejects_matrix_drift(self):
        def find(data, device_id):
            return next(d for d in data["devices"] if d["id"] == device_id)

        cases = {
            "unknown status": lambda d: find(d, "emulator-api-28").update(status="best-effort"),
            "unknown sim type": lambda d: find(d, "emulator-api-28").update(sim="dual"),
            "unknown evidence level": lambda d: find(d, "emulator-api-28").update(evidence="hearsay"),
            "missing key": lambda d: find(d, "emulator-api-28").pop("notes"),
            "unexpected key": lambda d: find(d, "emulator-api-28").update(serial="synthetic"),
            "duplicate id": lambda d: find(d, "emulator-api-34-plus").update(id="emulator-api-28"),
            "malformed id": lambda d: find(d, "emulator-api-28").update(id="Emulator_API_28"),
            "blank name": lambda d: find(d, "emulator-api-28").update(name=""),
            "blank notes": lambda d: find(d, "emulator-api-28").update(notes="  "),
            "api below the app floor": lambda d: find(d, "emulator-api-28").update(
                api={"min": self.min_sdk - 1, "max": self.min_sdk}
            ),
            "api above the app target": lambda d: find(d, "emulator-api-28").update(
                api={"min": self.min_sdk, "max": self.target_sdk + 1}
            ),
            "inverted api range": lambda d: find(d, "emulator-api-28").update(
                api={"min": 34, "max": 30}
            ),
            "missing api range on a supported class": lambda d: find(d, "emulator-api-28").update(
                api=None
            ),
            "api range on the host simulator": lambda d: find(
                d, "host-delivery-simulator"
            ).update(api={"min": self.min_sdk, "max": self.target_sdk}),
            "excluded class inside the app bounds": lambda d: find(
                d, "devices-below-api-28"
            ).update(api={"min": self.min_sdk, "max": self.target_sdk}),
            "unevaluated class outside the app bounds": lambda d: find(
                d, "other-physical-oem"
            ).update(api={"min": self.min_sdk - 2, "max": self.min_sdk}),
            "api with a boolean bound": lambda d: find(d, "emulator-api-28").update(
                api={"min": True, "max": self.target_sdk}
            ),
            "api with an extra field": lambda d: find(d, "emulator-api-28").update(
                api={"min": self.min_sdk, "max": self.target_sdk, "compile": 37}
            ),
            "dangling test path": lambda d: find(d, "emulator-api-28")["tests"].append(
                "android/app/src/androidTest/java/org/zrotext/gateway/AbsentDeviceTest.kt"
            ),
            "repeated test path": lambda d: find(d, "emulator-api-28")["tests"].append(
                find(d, "emulator-api-28")["tests"][0]
            ),
            # Built with chr(92) so the source never spells a UNC-shaped path
            # that the privacy guard would rightly reject.
            "backslash test path": lambda d: find(d, "emulator-api-28").update(
                tests=["android" + chr(92) + "app" + chr(92) + "build.gradle.kts"]
            ),
            "escaping test path": lambda d: find(d, "emulator-api-28").update(
                tests=["../Cargo.toml"]
            ),
            "emulator class without repeatable tests": lambda d: find(
                d, "emulator-api-28"
            ).update(tests=[]),
            "tests as a plain string": lambda d: find(d, "emulator-api-28").update(
                tests="docs/ANDROID-TESTING.md"
            ),
            "dangling source path": lambda d: find(d, "emulator-api-28").update(
                source="docs/ABSENT.md"
            ),
            "physical source outside docs": lambda d: find(
                d, "samsung-galaxy-s24-ultra"
            ).update(source="README.md"),
            "physical class without a doc record": lambda d: find(
                d, "samsung-galaxy-s24-ultra"
            ).update(name="Unrecorded Handset"),
            "excluded class named in the doc": lambda d: find(d, "devices-below-api-28").update(
                name=self.device("samsung-galaxy-s24-ultra")["name"]
            ),
            "evidence claimed without evaluation": lambda d: find(d, "other-physical-oem").update(
                evidence="emulator"
            ),
            "physical evidence downgraded to none": lambda d: find(
                d, "samsung-galaxy-s24-ultra"
            ).update(evidence="none"),
            "non-object device": lambda d: d["devices"].__setitem__(0, "samsung"),
            "empty devices list": lambda d: d.update(devices=[]),
            "schema version bump": lambda d: d.update(schema_version=3),
            "widened status enum": lambda d: d.update(statuses=list(d["statuses"]) + ["promised"]),
            "missing top-level key": lambda d: d.pop("note"),
            "missing repeatable runs catalog": lambda d: d.pop("repeatable_runs"),
            "empty repeatable runs catalog": lambda d: d.update(repeatable_runs=[]),
            "run with an unknown kind": lambda d: find_run(d, "api-28-emulator-suites").update(
                kind="adhoc"
            ),
            "run missing its tests": lambda d: find_run(d, "api-28-emulator-suites").pop("tests"),
            "run with a dangling test path": lambda d: find_run(d, "api-28-emulator-suites")[
                "tests"
            ].append("android/app/src/androidTest/java/org/zrotext/gateway/AbsentDeviceTest.kt"),
            "ci run naming an absent workflow": lambda d: find_run(d, "device-sim-suite").update(
                workflow=".github/workflows/absent.yml"
            ),
            "ci run naming an absent job": lambda d: find_run(d, "device-sim-suite").update(
                job="not-a-job"
            ),
            "ci run tests drift from the smoke allowlist": lambda d: find_run(
                d, "selected-device-tests"
            )["tests"].pop(),
            "supported class without a no-radio run": lambda d: find(d, "emulator-api-36-ci").update(
                no_radio_run=[]
            ),
            "excluded class with a no-radio run": lambda d: find(
                d, "devices-below-api-28"
            ).update(no_radio_run=["selected-device-tests"]),
            "unknown no-radio run reference": lambda d: find(d, "emulator-api-28")[
                "no_radio_run"
            ].append("not-a-run"),
            "repeated no-radio run reference": lambda d: find(d, "emulator-api-28")[
                "no_radio_run"
            ].append("api-28-emulator-suites"),
            "no-radio link to the opt-in radio run": lambda d: find(d, "emulator-api-28")[
                "no_radio_run"
            ].append("opt-in-radio-instrumentation"),
            "radio run naming a ci job": lambda d: find(d, "samsung-galaxy-s24-ultra").update(
                radio_run="selected-device-tests"
            ),
            "radio run naming an unknown run": lambda d: find(
                d, "samsung-galaxy-s24-ultra"
            ).update(radio_run="not-a-run"),
            "radio run on a SIM-less class": lambda d: find(d, "emulator-api-36-ci").update(
                radio_run="opt-in-radio-instrumentation"
            ),
            "device-sim evidence claiming a radio run": lambda d: find(
                d, "host-delivery-simulator"
            ).update(radio_run="opt-in-radio-instrumentation"),
            "device tests diverging from its runs": lambda d: find(d, "emulator-api-28")[
                "tests"
            ].append("android/app/src/androidTest/java/org/zrotext/gateway/SealedBodyDeviceTest.kt"),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.assertTrue(self.check(matrix=self.mutated(mutate)), label)

    def test_rejects_doc_drift(self):
        cases = {
            "unrecorded physical table row": self.doc.replace(
                f"{self.device('samsung-galaxy-s24-ultra')['name']}, one active SIM",
                "Unrecorded Handset, one active SIM",
            ),
            "dropped api floor": self.doc.replace(
                f"(API {self.min_sdk}) or later", "(API 21) or later"
            ),
            "dropped matrix link": self.doc.replace(
                "device-compatibility.json", "device-compat.json"
            ),
            "renamed physical section": self.doc.replace(
                "## Physical devices", "## Hardware runs"
            ),
            "dropped selected-device-tests mention": self.doc.replace(
                "selected-device-tests", "selected-device-test"
            ),
        }
        for label, doc in cases.items():
            with self.subTest(label):
                self.assertTrue(self.check(doc=doc), label)

    def test_every_claimed_configuration_links_a_repeatable_no_radio_run(self):
        for device in self.matrix["devices"]:
            with self.subTest(device=device["id"]):
                if device["status"] in ("supported", "partial"):
                    self.assertTrue(device["no_radio_run"])
                else:
                    self.assertEqual(device["no_radio_run"], [])
                    self.assertIsNone(device["radio_run"])

    def test_ci_job_references_resolve_in_the_workflows(self):
        for run in self.matrix["repeatable_runs"]:
            if run["kind"] == "ci-job":
                with self.subTest(run=run["id"]):
                    self.assertIsNone(
                        cdc._workflow_job_error(cdc.ROOT, run["workflow"], run["job"])
                    )
        self.assertIsNotNone(
            cdc._workflow_job_error(
                cdc.ROOT, ".github/workflows/android-device-smoke.yml", "not-a-job"
            )
        )
        self.assertIsNotNone(
            cdc._workflow_job_error(cdc.ROOT, ".github/workflows/absent.yml", "rust")
        )

    def test_documented_procedures_name_their_run_id(self):
        for run in self.matrix["repeatable_runs"]:
            if run["kind"] == "ci-job":
                continue
            with self.subTest(run=run["id"]):
                procedure = (cdc.ROOT / run["doc"]).read_text(encoding="utf-8")
                self.assertIn(run["id"], procedure)

    def test_documented_run_reference_requires_the_id_in_the_doc(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            procedure = root / "docs" / "PROCEDURE.md"
            procedure.write_text("a procedure that names no run", encoding="utf-8")
            run = {"id": "the-run", "kind": "documented-command", "doc": "docs/PROCEDURE.md", "tests": []}
            self.assertIn("does not mention the run id", cdc._run_reference_error(root, run))
            procedure.write_text("Repeatable run id: the-run.", encoding="utf-8")
            self.assertIsNone(cdc._run_reference_error(root, run))

    def test_ci_emulator_entry_matches_the_smoke_script_allowlist(self):
        allowlist = cdc.ci_emulator_allowlist(cdc.ROOT)
        self.assertEqual(set(find_run(self.matrix, "selected-device-tests")["tests"]), allowlist)
        ci_device = self.device("emulator-api-36-ci")
        self.assertEqual(set(ci_device["tests"]), allowlist)

    def test_radio_runs_stay_opt_in_and_off_ci(self):
        radio_runs = {
            run["id"] for run in self.matrix["repeatable_runs"] if run["kind"] == "opt-in-radio"
        }
        for device in self.matrix["devices"]:
            if device["radio_run"] is not None:
                with self.subTest(device=device["id"]):
                    self.assertIn(device["radio_run"], radio_runs)
                    self.assertNotEqual(device["sim"], "none")


if __name__ == "__main__":
    unittest.main()
