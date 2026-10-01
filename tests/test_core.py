import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ida_bsim_core import (
    BSimError, build_command, format_match_rows, ghidra_launcher,
    load_search_settings, normalize_database_url, query, ranked_matches,
    remember_database, save_search_settings, user_directories,
    validate_search_options,
)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "Ghidra release"
        (self.home / "support").mkdir(parents=True)
        (self.home / "support" / "analyzeHeadless").touch()
        (self.home / "support" / "analyzeHeadless.bat").touch()
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        (self.scripts / "IdaBsimQuery.java").touch()
        self.binary = self.root / "hello program"
        self.binary.write_bytes(b"original executable")
        self.cache = self.root / ".cache" / "ida-bsim"
        self.projects = self.root / "ida-bsim-projects"
        self.calls = []

    def fake_run(self, command, **kwargs):
        self.calls.append(command)
        if "-import" in command:
            (Path(command[1]) / (command[2] + ".gpr")).touch()
        Path(command[-1]).write_text(json.dumps({
            "ok": True, "matches": [{"function": "match", "similarity": 0.91,
                                      "significance": 22, "executable": "reference"}],
        }), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="analyzed", stderr="")

    def invoke(self, database_url="file:/home/test/bsimdb"):
        return query(self.home, database_url, self.binary,
                     self.scripts, self.cache, 0x250, 0x1234,
                     project_dir=self.projects)

    def test_import_once_then_reuse_analyzed_project(self):
        with patch("ida_bsim_core.subprocess.run", side_effect=self.fake_run):
            self.assertEqual(self.invoke()["matches"][0]["function"], "match")
            self.invoke()
        self.assertIn("-import", self.calls[0])
        self.assertIn("-process", self.calls[1])
        self.assertIn("-noanalysis", self.calls[1])
        self.assertIn("-readOnly", self.calls[1])
        self.assertEqual(self.calls[0][-7:-1],
                         ["file:/home/test/bsimdb", "250", "1234", "0.7", "0.0", "10"])
        self.assertEqual(self.calls[0][0], str(ghidra_launcher(self.home)))
        self.assertEqual(self.calls[0][1], str(self.projects))
        self.assertNotIn(".cache", self.calls[0][1])

    def test_changed_binary_gets_new_project(self):
        with patch("ida_bsim_core.subprocess.run", side_effect=self.fake_run):
            self.invoke()
            self.binary.write_bytes(b"changed executable")
            self.invoke()
        self.assertNotEqual(self.calls[0][2], self.calls[1][2])
        self.assertIn("-import", self.calls[1])

    def test_absolute_h2_file_path_becomes_file_url(self):
        database = self.root / "Master Db.mv.db"
        with patch("ida_bsim_core.subprocess.run", side_effect=self.fake_run):
            self.invoke(str(database))
        self.assertEqual(self.calls[0][-7], database.as_uri())

    def test_windows_h2_paths_and_urls(self):
        self.assertEqual(normalize_database_url(r"C:\Users\Ada\My Db.mv.db", windows=True),
                         "file:///C:/Users/Ada/My%20Db.mv.db")
        self.assertEqual(normalize_database_url(r"\\server\share\BSim\db", windows=True),
                         "file://server/share/BSim/db")
        self.assertEqual(normalize_database_url("file:///C:/BSim/db", windows=True),
                         "file:///C:/BSim/db")
        with self.assertRaises(BSimError):
            normalize_database_url(r"C:relative\db", windows=True)

    def test_platform_user_directories(self):
        linux = user_directories("linux", {"XDG_CONFIG_HOME": "/tmp/config",
                                           "XDG_CACHE_HOME": "/tmp/cache"}, self.root)
        self.assertEqual(linux, (Path("/tmp/config/ida-bsim"), Path("/tmp/cache/ida-bsim")))
        mac = user_directories("darwin", {}, self.root)
        self.assertEqual(mac, (self.root / "Library/Application Support/ida-bsim",
                               self.root / "Library/Caches/ida-bsim"))
        windows = user_directories("win32", {"APPDATA": "/tmp/Roaming",
                                              "LOCALAPPDATA": "/tmp/Local"}, self.root)
        self.assertEqual(windows, (Path("/tmp/Roaming/ida-bsim"),
                                   Path("/tmp/Local/ida-bsim/Cache")))
        fallback = user_directories("win32", {}, self.root)
        self.assertEqual(fallback[0], self.root / "AppData/Roaming/ida-bsim")

    def test_windows_launcher_is_used_for_validation_and_command(self):
        select_windows = lambda home: ghidra_launcher(home, windows=True)
        with patch("ida_bsim_core.ghidra_launcher", side_effect=select_windows), \
                patch("ida_bsim_core.subprocess.run", side_effect=self.fake_run):
            self.invoke()
        self.assertEqual(self.calls[0][0], str(self.home / "support" / "analyzeHeadless.bat"))

    def test_missing_windows_launcher_names_correct_file(self):
        (self.home / "support" / "analyzeHeadless.bat").unlink()
        with patch("ida_bsim_core.ghidra_launcher",
                   side_effect=lambda home: ghidra_launcher(home, windows=True)):
            with self.assertRaisesRegex(BSimError, r"support[/\\]analyzeHeadless\.bat"):
                self.invoke()

    def test_relative_database_path_fails_before_import(self):
        with patch("ida_bsim_core.subprocess.run") as run:
            with self.assertRaisesRegex(BSimError, "absolute H2 path or URL"):
                self.invoke("MasterDb.mv.db")
            run.assert_not_called()

    def test_unmapped_file_offset_uses_rva(self):
        command = build_command(self.home, self.cache, "test", self.binary,
                                self.scripts, "file:/db", None, 0x1234,
                                self.root / "result.json")
        self.assertEqual(command[-7:-1], ["file:/db", "-", "1234", "0.7", "0.0", "10"])

    def test_options_reach_ghidra_query(self):
        with patch("ida_bsim_core.subprocess.run", side_effect=self.fake_run):
            query(self.home, "file:/db", self.binary, self.scripts, self.cache,
                  0x250, 0x1234, project_dir=self.projects,
                  similarity=0.85, confidence=12.5, max_matches=25)
        self.assertEqual(self.calls[0][-7:-1],
                         ["file:/db", "250", "1234", "0.85", "12.5", "25"])

    def test_invalid_options_rejected_before_launch(self):
        with patch("ida_bsim_core.subprocess.run") as run:
            for options in ((-0.1, 0, 10), (1.1, 0, 10), ("nan", 0, 10),
                            (0.7, -1, 10), (0.7, "inf", 10), (0.7, 0, 0),
                            (0.7, 0, 1001), (0.7, 0, "1.5")):
                with self.subTest(options=options), self.assertRaises(BSimError):
                    query(self.home, "file:/db", self.binary, self.scripts,
                          self.cache, 0x250, 0x1234, project_dir=self.projects,
                          similarity=options[0], confidence=options[1],
                          max_matches=options[2])
            run.assert_not_called()

    def test_database_history_persists_and_deduplicates(self):
        settings_file = self.root / "config" / "ida-bsim" / "settings.json"
        self.assertEqual(load_search_settings(settings_file)["databases"], [])
        history = remember_database(["file:/one", "file:/two"], "file:/two")
        self.assertEqual(history, ["file:/two", "file:/one"])
        settings = {"databases": history, "similarity": 0.8,
                    "confidence": 8.5, "max_matches": 30}
        save_search_settings(settings_file, settings)
        self.assertEqual(load_search_settings(settings_file), settings)
        if os.name != "nt":
            self.assertEqual(settings_file.stat().st_mode & 0o777, 0o600)

    def test_malformed_history_defaults_without_crashing(self):
        settings_file = self.root / "settings.json"
        settings_file.write_text("{bad JSON", encoding="utf-8")
        self.assertEqual(load_search_settings(settings_file)["similarity"], 0.7)
        self.assertEqual(validate_search_options("0.3", "10", 12), (0.3, 10.0, 12))

    def test_results_show_selected_function_scores_and_ingest_date(self):
        result = {"matches": [
            {"similarity": 0.72, "significance": 9.1,
             "function": "match_low", "executable": "old.exe"},
            {"similarity": 0.95, "significance": 25.5,
             "function": "match_high", "executable": "new.exe",
             "ingest_date": "2026-09-30T12:30:00Z"},
        ]}
        rows = format_match_rows(result, "IDA_name", 0x140001020)
        self.assertEqual(rows[0], ["0.950", "25.50", "IDA_name", "match_high",
                                   "new.exe", "0x140001020", "2026-09-30"])
        self.assertEqual(rows[1][-1], "")
        self.assertEqual([match["function"] for match in ranked_matches(result)],
                         ["match_high", "match_low"])

    def test_missing_result_reports_headless_log(self):
        with patch("ida_bsim_core.subprocess.run", return_value=
                   subprocess.CompletedProcess([], 1, stdout="failure details", stderr="")):
            with self.assertRaisesRegex(BSimError, "failure details"):
                self.invoke()

    def test_script_error_surfaces_as_exception(self):
        def fail(command, **kwargs):
            Path(command[-1]).write_text('{"ok": false, "matches": [], "error": "No function"}')
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with patch("ida_bsim_core.subprocess.run", side_effect=fail):
            with self.assertRaisesRegex(BSimError, "No function"):
                self.invoke()

    def test_h2_lock_error_explains_required_action(self):
        def locked(command, **kwargs):
            Path(command[-1]).write_text(json.dumps({
                "ok": False, "matches": [],
                "error": "java.lang.IllegalStateException: BSim database: Database already in use by another process",
            }), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="Java warnings")

        with patch("ida_bsim_core.subprocess.run", side_effect=locked):
            with self.assertRaisesRegex(BSimError, "Close the Ghidra BSim connection") as caught:
                self.invoke("file:/home/test/MasterDb.mv.db")
        self.assertIn("PostgreSQL", str(caught.exception))
        self.assertNotIn("Java warnings", str(caught.exception))

    def test_missing_release_is_reported_before_launch(self):
        with self.assertRaisesRegex(BSimError, "analyzeHeadless"):
            query(self.root / "missing", "file:/db", self.binary,
                  self.scripts, self.cache, None, 0)

    def test_hidden_ghidra_project_path_rejected_before_launch(self):
        with patch("ida_bsim_core.subprocess.run") as run:
            with self.assertRaisesRegex(BSimError, "dot-prefixed"):
                query(self.home, "file:/db", self.binary, self.scripts,
                      self.cache, 0x250, 0x1234,
                      project_dir=self.cache / "projects")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
