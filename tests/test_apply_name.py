"""Exercise chooser's IDA-facing rename action with a minimal API stub."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


PLUGIN_FILE = Path(__file__).resolve().parents[1] / "ida_bsim.py"


class ApplyNameTests(unittest.TestCase):
    def setUp(self):
        self.current_name = "sub_140001020"
        self.warnings = []
        self.renames = []
        self.idb_path = "/home/jex/crackme.i64"

        kernwin = types.ModuleType("ida_kernwin")
        outer = self

        class FakeChoose:
            def __init__(self, title, columns):
                self.title = title
                self.columns = columns

            def AddCommand(self, title):
                self.command = title
                return 0

            def Refresh(self):
                pass

        kernwin.Choose = FakeChoose
        kernwin.Form = type("Form", (), {})
        kernwin.warning = self.warnings.append
        kernwin.msg = lambda message: None
        kernwin.ask_str = lambda default, history, prompt: "clean_name"

        funcs = types.ModuleType("ida_funcs")
        funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea)
        funcs.get_func_name = lambda ea: self.current_name

        loader = types.ModuleType("ida_loader")
        loader.PATH_TYPE_IDB = 1
        loader.get_path = lambda kind: self.idb_path

        name = types.ModuleType("ida_name")
        name.SN_CHECK = 1
        name.SN_NOWARN = 2
        name.is_ident = lambda candidate: candidate.isidentifier()
        name.get_name_ea = lambda invalid, candidate: getattr(self, "owner", invalid)

        def set_name(ea, candidate, flags):
            outer.renames.append((ea, candidate, flags))
            outer.current_name = candidate
            return True

        name.set_name = set_name
        api = types.ModuleType("ida_idaapi")
        api.plugin_t = type("plugin_t", (), {})
        api.PLUGIN_KEEP = 2
        api.BADADDR = (1 << 64) - 1

        modules = {"ida_kernwin": kernwin, "ida_funcs": funcs, "ida_loader": loader,
                   "ida_name": name, "ida_idaapi": api,
                   "ida_nalt": types.ModuleType("ida_nalt")}
        with patch.dict(sys.modules, modules):
            spec = importlib.util.spec_from_file_location("ida_bsim_test_plugin", PLUGIN_FILE)
            plugin = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin)
        self.chooser = plugin.MatchChooser(0x140001020, self.current_name,
                                           self.idb_path, {"matches": [
                                               {"function": "low_name", "executable": "old.exe",
                                                "similarity": 0.72, "significance": 9},
                                               {"function": "winning_name", "executable": "new.exe",
                                                "similarity": 0.95, "significance": 20},
                                           ]})

    def test_right_click_applies_selected_ranked_match(self):
        self.chooser.OnCommand(0, self.chooser._apply_name_command)
        self.assertEqual(self.renames[0][:2], (0x140001020, "winning_name"))
        self.assertEqual([row[2] for row in self.chooser.rows], ["winning_name"] * 2)

    def test_collision_and_other_command_leave_idb_unchanged(self):
        self.owner = 0x140002000
        self.chooser.OnCommand(0, self.chooser._apply_name_command)
        self.assertEqual(self.renames, [])
        self.assertIn("already belongs", self.warnings[-1])
        del self.owner
        self.chooser.OnCommand(0, self.chooser._apply_name_command + 1)
        self.assertEqual(self.renames, [])

    def test_results_from_other_database_cannot_rename_here(self):
        self.idb_path = "/home/jex/other.i64"
        self.chooser.OnCommand(0, self.chooser._apply_name_command)
        self.assertEqual(self.renames, [])
        self.assertIn("another IDA database", self.warnings[-1])

    def test_invalid_bsim_name_can_be_edited_before_apply(self):
        self.chooser.matches[0]["function"] = "namespace::method"
        self.chooser.OnCommand(0, self.chooser._apply_name_command)
        self.assertEqual(self.renames[0][1], "clean_name")


if __name__ == "__main__":
    unittest.main()
