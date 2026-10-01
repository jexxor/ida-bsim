# IDA BSim (IDA 9.3 + headless Ghidra)

IDA plugin for querying **Ghidra's real BSim** signatures. IDA selects a function and displays matches; a local Ghidra release imports/analyzes the original binary, produces its normalized decompiler signature, and queries a BSim database. No Hex-Rays decompiler or native IDA SDK build required.

## Requirements

- IDA 9.3 with IDAPython on Linux, macOS, or Windows.
- A **built Ghidra release** for the same host OS, with `support/analyzeHeadless` (Windows: `support/analyzeHeadless.bat`) and a suitable JDK (Ghidra 12.1.x requires JDK 25). A source checkout alone is insufficient. Use a release matching the Ghidra BSim API in this project; the companion script follows `Ghidra/Features/BSim/ghidra_scripts/QueryFunction.java`.
- A populated BSim database, e.g. local H2 `file:/home/user/bsim/db`, and original binary still accessible on disk. Reference functions must have been ingested into that database.

## Install on the IDA host

Copy from this project to your IDA user plugins directory (`~/.idapro/plugins` on Linux/macOS, `%APPDATA%\Hex-Rays\IDA Pro\plugins` on Windows).

Linux/macOS:

```sh
mkdir -p ~/.idapro/plugins/ida_bsim_scripts
cp ida_bsim.py ida_bsim_core.py ~/.idapro/plugins/
cp ghidra_scripts/IdaBsimQuery.java ~/.idapro/plugins/ida_bsim_scripts/
```

Windows PowerShell:

```powershell
$plugins = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins'
New-Item -ItemType Directory -Force (Join-Path $plugins 'ida_bsim_scripts') | Out-Null
Copy-Item ida_bsim.py, ida_bsim_core.py $plugins
Copy-Item ghidra_scripts/IdaBsimQuery.java (Join-Path $plugins 'ida_bsim_scripts')
```

Set paths before launching IDA (or let plugin prompt for Ghidra/database paths on first use). Linux/macOS shell:

```sh
export JAVA_HOME=/path/to/jdk-25
export IDA_BSIM_GHIDRA_HOME=/path/to/ghidra_release
export IDA_BSIM_DB_URL="file:$HOME/bsim/db"
/path/to/ida
```

Windows PowerShell (launch IDA from this session so it inherits variables):

```powershell
$env:JAVA_HOME = 'C:\path\to\jdk-25'
$env:IDA_BSIM_GHIDRA_HOME = 'C:\path\to\ghidra_release'
$env:IDA_BSIM_DB_URL = 'C:\Users\Ada\BSim\MasterDb.mv.db'
& 'C:\path\to\ida.exe'
```

`IDA_BSIM_DB_URL` also accepts an **absolute path** to an existing H2 `.mv.db` file (`/home/user/BSim/MasterDb.mv.db`, `C:\Users\Ada\BSim\MasterDb.mv.db`, or a Windows UNC path). Plugin converts native paths to `file:` URLs, escaping spaces as needed. Relative paths are not supported.

Open a binary in IDA, put cursor inside a function, then run **Edit → Plugins → IDA BSim: query function**. **BSim Search Functions** shows selected IDA function, an editable list of previously used databases, and similarity threshold (0–1), confidence threshold (BSim significance, nonnegative), and max matches per function (1–1000). Press **Search** or **Cancel**. Settings and up to 20 recent database URLs are saved in `~/.config/ida-bsim/settings.json` on Linux, `~/Library/Application Support/ida-bsim/settings.json` on macOS, or `%APPDATA%\ida-bsim\settings.json` on Windows. `XDG_CONFIG_HOME` overrides these defaults. Set `IDA_BSIM_DB_URL` to preselect a database on IDA startup.

Initial import/analysis can take minutes; subsequent queries reuse cached Ghidra project. **Function matches - N results** displays similarity, confidence, IDA function name, matching function name, executable name, IDA location, and BSim ingest date. Blank ingest date means database has none. Right-click a result → **Apply Name** to rename selected IDA function to matching BSim name. Invalid identifier can be edited; collisions are rejected. Plugin never renames automatically.

Ghidra analysis projects: `~/ida-bsim-projects` by default; override with `IDA_BSIM_PROJECT_DIR` (absolute path). **Do not use `~/.cache` or any dot-prefixed directory in that path**: Ghidra rejects them. Temporary query results use `~/.cache/ida-bsim` on Linux, `~/Library/Caches/ida-bsim` on macOS, or `%LOCALAPPDATA%\ida-bsim\Cache` on Windows (`XDG_CACHE_HOME` overrides). Each different input binary SHA-256 gets its own project. H2 databases can be locked by another Ghidra process: close the Ghidra UI using the same H2 DB before querying.

**`Database already in use by another process`:** local H2 BSim databases permit only one owning process. Disconnect that database in Ghidra or close Ghidra and other headless BSim sessions, then retry in IDA. On Linux, `fuser -v /absolute/path/to/MasterDb.mv.db` can help identify the process. Leave database and lock files intact while diagnosing. Use PostgreSQL or Elasticsearch BSim if simultaneous Ghidra/IDA queries are required.

## Create a small H2 database (if you don't already have one)

Follow [Ghidra's BSim tutorial](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.md). For an existing Ghidra project containing **analyzed reference binaries**:

```sh
GHIDRA=/path/to/ghidra_release
mkdir -p "$HOME/bsim" "$HOME/bsim-sigs"
"$GHIDRA/support/bsim" createdatabase "file:$HOME/bsim/db" medium_nosize
"$GHIDRA/support/bsim" generatesigs "ghidra:$HOME/ghidra-projects/References" \
  "$HOME/bsim-sigs" --bsim "file:$HOME/bsim/db"
"$GHIDRA/support/bsim" commitsigs "file:$HOME/bsim/db" "$HOME/bsim-sigs"
```

On Windows, use `support\bsim.bat` from PowerShell and Windows paths or `file:///C:/...` URLs instead. Ghidra and Java must have permission to read both input binary and database.

`ghidra:/` takes a local project path and name (single slash after scheme). Adjust path/project name and consult your installed release's `GhidraClass/BSim` documentation for database setup. Reference project and database are separate; BSim database stores signatures and metadata, not decompiled source.

## Mapping and limits

Plugin tries **file offset** first, then function RVA relative to each tool's image base. Ghidra returns whether it matched exact function entry or a containing function; check this before trusting a name. Ghidra may recognize different function boundaries than IDA. Queries use **on-disk input binary**, not IDA database patches or unpacked runtime memory. `No Ghidra function` means review mapping or analysis; `No matches` means no candidate above similarity threshold 0.7 in your database.

For initial host testing, choose a function from a binary **already present in the reference database**. You should see a high-scoring self-match. Then try a related version built with different options.

## Development checks

```sh
python3 -m unittest discover -s tests -v
```

Offline tests cover command construction, cache reuse, and errors. Ghidra Java script compilation and end-to-end matching must be tested on a host with a runnable Ghidra release.
