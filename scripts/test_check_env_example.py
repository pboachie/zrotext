"""Fixture flags must not conceal production environment settings."""
import unittest
from pathlib import Path

try:
    from . import check_env_example as env
except ImportError:
    import check_env_example as env


class RuntimeReadsTest(unittest.TestCase):
    def test_custody_markers_are_excluded_only_in_the_test_module(self):
        flags = {"TEMP", "ZT_CUSTODY_NATIVE_CASE"}
        source = ";".join(f'std::env::var("{flag}")' for flag in flags)
        fixture = "crates/owner-cli/src/windows/custody_sign/tests.rs"
        self.assertEqual(env.runtime_reads(source, fixture), set())
        for runtime in ["crates/owner-cli/src/windows/custody_sign.rs",
                        "crates/server/src/main.rs"]:
            self.assertEqual(env.runtime_reads(source, runtime), flags)
        module = Path(env.ROOT, "crates/owner-cli/src/windows/custody_sign.rs").read_text(encoding="utf-8")
        self.assertRegex(module, r'#\[cfg\(test\)\]\s*mod tests;')

    def test_archive_marker_is_excluded_only_in_its_fixture(self):
        source = 'std::env::var_os("ZT_ARCHIVE_INTEROP"); optional_bool("CONVERSATION_ENABLED")'
        self.assertEqual(env.runtime_reads(source, "crates/root-material/src/archive_backup/tests.rs"),
                         {"CONVERSATION_ENABLED"})
        self.assertEqual(env.runtime_reads(source, "crates/server/src/main.rs"),
                         {"ZT_ARCHIVE_INTEROP", "CONVERSATION_ENABLED"})

    def test_native_temp_exception_does_not_hide_runtime_temp(self):
        source = 'std::env::var("TEMP"); required("RUNTIME_SETTING")'
        self.assertEqual(env.runtime_reads(source, "crates/owner-cli/src/windows/conversation_refresh/native_tests.rs"),
                         {"RUNTIME_SETTING"})
        self.assertEqual(env.runtime_reads(source, "crates/server/src/main.rs"),
                         {"TEMP", "RUNTIME_SETTING"})

    def test_smtp_aliases_still_require_both_settings(self):
        self.assertEqual(env.runtime_reads('smtp_alias("SMTP_PRIMARY", "SMTP_LEGACY")', "crates/server/src/main.rs"),
                         {"SMTP_PRIMARY", "SMTP_LEGACY"})

    def test_activation_markers_are_not_exempt_in_production(self):
        flags = {"TEMP", "ZT_ACTIVATION_NATIVE_CASE", "ZT_ACTIVATION_INTEROP_NOW",
                 "ZT_ACTIVATION_INTEROP_PROPOSAL_HEX"}
        source = ";".join(f'std::env::var("{flag}")' for flag in flags)
        self.assertEqual(env.runtime_reads(source, "crates/owner-cli/src/windows/conversation_activation/native_tests.rs"), set())
        self.assertEqual(env.runtime_reads(source, "crates/server/src/main.rs"), flags)

    def test_inline_marker_before_test_module_remains_runtime(self):
        marker = 'std::env::var_os("ZT_ACTIVATION_INTEROP")'
        tests = ('#[cfg(test)]\nmod tests {\n    #[test]\n'
                 '    fn existing_root_signs_only_preserved_activation_and_public_interop() {\n'
                 '        ' + marker + ';\n    }\n}')
        path = "crates/root-material/src/conversation_activation.rs"
        self.assertEqual(env.runtime_reads(tests, path), set())
        self.assertEqual(env.runtime_reads(marker + ';\n' + tests, path), {"ZT_ACTIVATION_INTEROP"})
        self.assertEqual(env.runtime_reads(tests + '\n' + marker + ';', path), {"ZT_ACTIVATION_INTEROP"})

    def test_archive_fixture_is_only_compiled_for_tests(self):
        module = Path(env.ROOT, "crates/root-material/src/archive_backup.rs").read_text(encoding="utf-8")
        self.assertRegex(module, r'#\[cfg\(test\)\]\s*#\[path = "archive_backup/tests.rs"\]\s*mod tests;')
        activation = Path(env.ROOT, "crates/owner-cli/src/windows/conversation_activation.rs").read_text(encoding="utf-8")
        self.assertRegex(activation, r'#\[cfg\(test\)\]\s*mod native_tests;')


if __name__ == "__main__":
    unittest.main()
