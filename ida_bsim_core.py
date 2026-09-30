"""Headless Ghidra runner. This module does not import IDA and can be tested alone."""

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlparse


SCRIPT_NAME = "IdaBsimQuery.java"
DEFAULT_SIMILARITY = 0.7
DEFAULT_CONFIDENCE = 0.0
DEFAULT_MAX_MATCHES = 10
MAX_DATABASE_HISTORY = 20


class BSimError(Exception):
    pass


def validate_search_options(similarity, confidence, max_matches):
    try:
        similarity = float(similarity)
        confidence = float(confidence)
        maximum = int(max_matches)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BSimError("Similarity, confidence, and max matches must be numbers") from exc
    if not math.isfinite(similarity) or not 0.0 <= similarity <= 1.0:
        raise BSimError("Similarity threshold must be between 0 and 1")
    if not math.isfinite(confidence) or confidence < 0:
        raise BSimError("Confidence threshold must be nonnegative")
    if isinstance(max_matches, float) and not max_matches.is_integer():
        raise BSimError("Max matches per function must be an integer")
    if not 1 <= maximum <= 1000:
        raise BSimError("Max matches per function must be between 1 and 1000")
    return similarity, confidence, maximum


def remember_database(databases, selected):
    selected = normalize_database_url(selected)
    return [selected] + [db for db in databases if db != selected][:MAX_DATABASE_HISTORY - 1]


def ranked_matches(result):
    """Keep visible chooser row order aligned with its underlying BSim match."""
    return sorted(result["matches"],
                  key=lambda item: (float(item["similarity"]), float(item["significance"])),
                  reverse=True)


def format_match_rows(result, query_name, query_ea):
    """Display selected IDA function alongside matched Ghidra metadata."""
    rows = []
    for match in ranked_matches(result):
        rows.append([
            "{:.3f}".format(float(match["similarity"])),
            "{:.2f}".format(float(match["significance"])),
            str(query_name), str(match["function"]), str(match["executable"]),
            "0x{:X}".format(query_ea), str(match.get("ingest_date", ""))[:10],
        ])
    return rows


def load_search_settings(path):
    defaults = {"databases": [], "similarity": DEFAULT_SIMILARITY,
                "confidence": DEFAULT_CONFIDENCE, "max_matches": DEFAULT_MAX_MATCHES}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return defaults
        databases = data.get("databases", [])
        if isinstance(databases, list):
            defaults["databases"] = [db for db in databases[:MAX_DATABASE_HISTORY]
                                     if isinstance(db, str) and db.strip()]
        values = validate_search_options(data.get("similarity", DEFAULT_SIMILARITY),
                                         data.get("confidence", DEFAULT_CONFIDENCE),
                                         data.get("max_matches", DEFAULT_MAX_MATCHES))
        defaults.update(zip(("similarity", "confidence", "max_matches"), values))
    except (OSError, ValueError, BSimError):
        pass
    return defaults


def save_search_settings(path, settings):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Atomic replace; tempfile is created with private permissions for URLs with credentials.
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix=".settings-", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            json.dump(settings, tmp)
            tmp.write("\n")
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def normalize_database_url(value):
    """Accept Ghidra BSim URLs or absolute paths to local H2 databases."""
    value = value.strip()
    if not value:
        raise BSimError("BSim database URL is empty")
    if value.startswith(("/", "~")):
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise BSimError("BSim database path must be absolute: " + value)
        return path.resolve().as_uri()
    url = urlparse(value)
    if url.scheme in ("file", "postgresql", "https", "elastic", "ghidra") and url.path:
        return value
    raise BSimError("BSim database must be an absolute H2 path or URL (e.g. file:/home/me/bsim/db)")


def _digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_command(ghidra_home, project_dir, project_name, executable,
                  script_dir, database_url, file_offset, rva, output_file,
                  cached=False, similarity=DEFAULT_SIMILARITY,
                  confidence=DEFAULT_CONFIDENCE, max_matches=DEFAULT_MAX_MATCHES):
    """Build argv without a shell; script args follow -postScript last."""
    launcher = Path(ghidra_home) / "support" / "analyzeHeadless"
    command = [str(launcher), str(project_dir), project_name]
    if cached:
        command += ["-process", Path(executable).name, "-noanalysis", "-readOnly"]
    else:
        command += ["-import", str(executable)]
    command += [
        "-scriptPath", str(script_dir),
        "-postScript", SCRIPT_NAME, database_url,
        "-" if file_offset is None else format(file_offset, "x"),
        format(rva, "x"), str(similarity), str(confidence),
        str(max_matches), str(output_file),
    ]
    return command


def query(ghidra_home, database_url, executable, script_dir, cache_dir,
          file_offset, rva, timeout=600, project_dir=None,
          similarity=DEFAULT_SIMILARITY, confidence=DEFAULT_CONFIDENCE,
          max_matches=DEFAULT_MAX_MATCHES):
    """Return query JSON. Import/analyze binary once per SHA-256 into local project."""
    ghidra_home = Path(ghidra_home).expanduser().resolve()
    executable = Path(executable).expanduser().resolve()
    script_dir = Path(script_dir).expanduser().resolve()
    cache_dir = Path(cache_dir).expanduser().resolve()
    project_dir = Path(project_dir or (Path.home() / "ida-bsim-projects")).expanduser().resolve()

    if not (ghidra_home / "support" / "analyzeHeadless").is_file():
        raise BSimError("Ghidra release missing support/analyzeHeadless: " + str(ghidra_home))
    if not (script_dir / SCRIPT_NAME).is_file():
        raise BSimError("Ghidra script missing: " + str(script_dir / SCRIPT_NAME))
    if not executable.is_file():
        raise BSimError("Input binary missing: " + str(executable))
    database_url = normalize_database_url(database_url)
    similarity, confidence, max_matches = validate_search_options(
        similarity, confidence, max_matches)
    if rva < 0 or (file_offset is not None and file_offset < 0):
        raise BSimError("Function RVA and file offset must be nonnegative")
    if any(part.startswith(".") for part in project_dir.parts):
        raise BSimError("Ghidra rejects dot-prefixed directories in project paths: {}. "
                        "Set IDA_BSIM_PROJECT_DIR to a visible directory.".format(project_dir))

    project_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    project_name = "ida_bsim_" + _digest_file(executable)[:24]
    cached = (project_dir / (project_name + ".gpr")).exists()

    with tempfile.TemporaryDirectory(prefix="query-", dir=cache_dir) as temp:
        output_file = Path(temp) / "result.json"
        command = build_command(
            ghidra_home, project_dir, project_name, executable, script_dir,
            database_url, file_offset, rva, output_file, cached=cached,
            similarity=similarity, confidence=confidence, max_matches=max_matches)
        try:
            run = subprocess.run(command, capture_output=True, text=True,
                                 errors="replace", timeout=timeout, check=False,
                                 env=os.environ.copy())
        except subprocess.TimeoutExpired as exc:
            raise BSimError("Ghidra headless timed out after {} seconds".format(timeout)) from exc
        except OSError as exc:
            raise BSimError("Could not start Ghidra: " + str(exc)) from exc

        log = "\n".join((run.stdout + "\n" + run.stderr).splitlines()[-30:])
        if not output_file.is_file():
            raise BSimError("Ghidra did not produce a result (exit {}):\n{}".format(run.returncode, log))
        try:
            result = json.loads(output_file.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise BSimError("Invalid Ghidra result:\n" + log) from exc
        if not isinstance(result, dict) or not isinstance(result.get("matches"), list):
            raise BSimError("Unexpected Ghidra result format:\n" + log)
        if not result.get("ok", False):
            error = str(result.get("error", "BSim query failed"))
            if (urlparse(database_url).scheme == "file"
                    and "Database already in use by another process" in error):
                raise BSimError(
                    "H2 BSim database is locked: {}. Close the Ghidra BSim connection "
                    "or other process using this database, then retry. For simultaneous "
                    "clients, use a PostgreSQL or Elasticsearch BSim database.".format(database_url))
            raise BSimError(error + "\n" + log)
        if run.returncode != 0:
            raise BSimError("Ghidra exited with code {}:\n{}".format(run.returncode, log))
        return result
