"""IDA 9.3 front end for Ghidra's headless BSim function search."""

import os
from pathlib import Path
import sys
import threading

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt


# IDA installations do not all add their plugins directory to Python's sys.path.
_PLUGIN_DIR = Path(__file__).resolve().parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))
from ida_bsim_core import (  # noqa: E402
    BSimError, format_match_rows, load_search_settings, normalize_database_url, query,
    ranked_matches,
    remember_database, save_search_settings, validate_search_options,
)


class SearchForm(ida_kernwin.Form):
    """Function-scoped query options, including an editable database history."""

    def __init__(self, function_label, databases, settings):
        F = ida_kernwin.Form
        items = databases or ["file:/"]
        super().__init__(
            """STARTITEM 0
BUTTON YES* Search
BUTTON CANCEL Cancel
BSim Search Functions

Selected function: {cFunction}
<BSim database (choose or enter path/URL):{cDatabase}>

Options
<Similarity threshold (0-1):{iSimilarity}>
<Confidence threshold:{iConfidence}>
<Max matches per function:{iMaxMatches}>
""",
            {
                "cFunction": F.StringLabel(function_label),
                "cDatabase": F.DropdownListControl(items=items, readonly=False,
                                                    selval=items[0]),
                "iSimilarity": F.StringInput(swidth=12),
                "iConfidence": F.StringInput(swidth=12),
                "iMaxMatches": F.NumericInput(tp=F.FT_DEC),
            },
        )
        self.Compile()
        self.iSimilarity.value = str(settings["similarity"])
        self.iConfidence.value = str(settings["confidence"])
        self.iMaxMatches.value = settings["max_matches"]

    def ask(self):
        try:
            if self.Execute() != 1:
                return None
            return (self.cDatabase.value, self.iSimilarity.value,
                    self.iConfidence.value, self.iMaxMatches.value)
        finally:
            self.Free()


class MatchChooser(ida_kernwin.Choose):
    def __init__(self, query_ea, query_name, idb_path, result):
        super().__init__(
            "Function matches - {} results".format(len(result["matches"])),
            [["Similarity", 12], ["Confidence", 15], ["Function Name", 35],
             ["Matching Function Name", 35], ["Exe Name", 32],
             ["Location", 18], ["Ingest Date", 16]])
        self.query_ea = query_ea
        self.idb_path = idb_path
        self.matches = ranked_matches(result)
        self.rows = format_match_rows(result, query_name, query_ea)
        self._apply_name_command = self.AddCommand("Apply Name")

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]

    def OnGetEA(self, n):
        return self.query_ea

    def OnCommand(self, n, cmd_id):
        if cmd_id != self._apply_name_command or not 0 <= n < len(self.matches):
            return
        if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            ida_kernwin.warning("BSim results belong to another IDA database; search again")
            return
        function = ida_funcs.get_func(self.query_ea)
        if function is None or function.start_ea != self.query_ea:
            ida_kernwin.warning("Selected function no longer exists at this address")
            return

        candidate = str(self.matches[n]["function"])
        if not ida_name.is_ident(candidate):
            candidate = ida_kernwin.ask_str(candidate, 0, "Edit BSim name to a valid IDA identifier")
            if candidate is None:
                return
            candidate = candidate.strip()
        if not candidate or not ida_name.is_ident(candidate):
            ida_kernwin.warning("BSim name is not a valid IDA identifier")
            return

        current = ida_funcs.get_func_name(self.query_ea)
        if current == candidate:
            ida_kernwin.msg("[ida-bsim] Function is already named {}\n".format(candidate))
            return
        owner = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if owner != ida_idaapi.BADADDR and owner != self.query_ea:
            ida_kernwin.warning("Name '{}' already belongs to 0x{:X}".format(candidate, owner))
            return
        if not ida_name.set_name(self.query_ea, candidate, ida_name.SN_CHECK | ida_name.SN_NOWARN):
            ida_kernwin.warning("IDA could not apply name '{}'".format(candidate))
            return
        applied_name = ida_funcs.get_func_name(self.query_ea)
        for row in self.rows:
            row[2] = applied_name
        self.Refresh()
        ida_kernwin.msg("[ida-bsim] Renamed 0x{:X}: {} -> {}\n".format(
            self.query_ea, current, applied_name))


class IDABSimPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Query Ghidra BSim from IDA"
    help = "Match selected function against a Ghidra BSim database"
    wanted_name = "IDA BSim: query function"
    wanted_hotkey = ""

    def init(self):
        self._busy = False
        self._closed = False
        self._chooser = None
        self._ghidra_home = os.environ.get("IDA_BSIM_GHIDRA_HOME", "")
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        self._settings_path = config_home / "ida-bsim" / "settings.json"
        self._search_settings = load_search_settings(self._settings_path)
        preferred_db = os.environ.get("IDA_BSIM_DB_URL", "").strip()
        if preferred_db:
            try:
                self._search_settings["databases"] = remember_database(
                    self._search_settings["databases"], preferred_db)
            except BSimError:
                ida_kernwin.msg("[ida-bsim] Invalid IDA_BSIM_DB_URL; select database in search dialog\n")
        return ida_idaapi.PLUGIN_OK

    def term(self):
        self._closed = True

    def _ghidra_settings(self):
        if not self._ghidra_home:
            value = ida_kernwin.ask_str("", 0, "Ghidra release directory (contains support/analyzeHeadless)")
            if value is None:
                return False
            self._ghidra_home = value.strip()
        return bool(self._ghidra_home)

    def run(self, arg):
        if self._busy:
            ida_kernwin.msg("[ida-bsim] Query already running\n")
            return
        func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        if func is None:
            ida_kernwin.warning("Move cursor inside a function before querying BSim")
            return
        executable = Path(ida_nalt.get_input_file_path())
        if not executable.is_file():
            ida_kernwin.warning("Original input binary is unavailable: {}".format(executable))
            return
        rva = func.start_ea - ida_nalt.get_imagebase()
        if rva < 0:
            ida_kernwin.warning("Function address precedes image base; cannot map into Ghidra")
            return
        file_offset = ida_loader.get_fileregion_offset(func.start_ea)
        if file_offset < 0 or file_offset == ida_idaapi.BADADDR:
            file_offset = None
        if not self._ghidra_settings():
            return

        query_name = ida_funcs.get_func_name(func.start_ea)
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        label = "{} @ {:X}".format(query_name, func.start_ea)
        response = SearchForm(label, self._search_settings["databases"],
                              self._search_settings).ask()
        if response is None:
            return
        try:
            database_url = normalize_database_url(response[0])
            similarity, confidence, max_matches = validate_search_options(*response[1:])
        except BSimError as exc:
            ida_kernwin.warning(str(exc))
            return
        self._search_settings = {
            "databases": remember_database(self._search_settings["databases"], database_url),
            "similarity": similarity, "confidence": confidence, "max_matches": max_matches,
        }
        try:
            save_search_settings(self._settings_path, self._search_settings)
        except OSError as exc:
            ida_kernwin.msg("[ida-bsim] Cannot save database history: {}\n".format(exc))

        script_dir = _PLUGIN_DIR / "ida_bsim_scripts"
        if not script_dir.is_dir():
            script_dir = _PLUGIN_DIR / "ghidra_scripts"  # run directly from source checkout
        cache_dir = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "ida-bsim"
        project_dir = Path(os.environ.get("IDA_BSIM_PROJECT_DIR", str(Path.home() / "ida-bsim-projects")))

        self._busy = True
        ida_kernwin.msg("[ida-bsim] Querying {} @ {:X}; initial analysis may take minutes\n".format(
            executable.name, func.start_ea))
        worker = threading.Thread(
            target=self._query_in_background,
            args=(func.start_ea, query_name, idb_path, str(executable), str(script_dir), str(cache_dir),
                  str(project_dir), database_url, file_offset, rva,
                  similarity, confidence, max_matches),
            daemon=True,
        )
        worker.start()

    def _query_in_background(self, ea, query_name, idb_path, executable, script_dir, cache_dir,
                             project_dir, database_url, file_offset, rva,
                             similarity, confidence, max_matches):
        try:
            result = query(self._ghidra_home, database_url, executable, script_dir,
                           cache_dir, file_offset, rva, project_dir=project_dir,
                           similarity=similarity, confidence=confidence,
                           max_matches=max_matches)
            error = None
        except (BSimError, OSError, ValueError, KeyError) as exc:
            result = None
            error = str(exc)

        def display():
            if self._closed:
                return 1
            self._busy = False
            if error:
                ida_kernwin.msg("[ida-bsim] {}\n".format(error))
                ida_kernwin.warning("BSim query failed. See IDA Output for details.")
            else:
                if not result["matches"]:
                    ida_kernwin.msg("[ida-bsim] No matches above similarity {} and confidence {}\n".format(
                        similarity, confidence))
                ida_kernwin.msg("[ida-bsim] {} matches; mapped by {}, exact entry: {}\n".format(
                    len(result["matches"]), result.get("mapped_by", "unknown"),
                    result.get("exact_entry", False)))
                self._chooser = MatchChooser(ea, query_name, idb_path, result)
                self._chooser.Show(False)
            return 1

        ida_kernwin.execute_sync(display, ida_kernwin.MFF_FAST)


def PLUGIN_ENTRY():
    return IDABSimPlugin()
