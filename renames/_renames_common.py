# -*- coding: utf-8 -*-
# Shared logic for apply_renames_low.py / apply_renames_high.py.
# Loaded via execfile() from the per-tier shim. Jython 2.7 (Ghidra default).
#
# Globals expected from the caller before exec:
#   TIER  — 'LOW' or 'HIGH'
#   TSV   — absolute path to the *primary* tsv data file. Sibling files matching
#           the glob `<basename_stem>*.tsv` in the same directory are also
#           loaded and applied within the same tier (alphabetical order). This
#           lets us split a tier across multiple domain-specific files
#           (e.g. renames_high.tsv + renames_high_sound.tsv) — handy when the
#           HIGH tier grows large enough to want sub-files per subsystem.
# Globals available from Ghidra Jython runtime:
#   currentProgram, getSymbolAt, getFunctionAt, getFunctionContaining,
#   createLabel, toAddr, println

import glob as _glob
import os as _os

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.label import RenameLabelCmd
from ghidra.app.cmd.function import CreateFunctionCmd

def _log(msg):
    println("[%s] %s" % (TIER, msg))

def _parse_tsv(path):
    rows = []
    f = open(path)
    try:
        for raw in f:
            ln = raw.rstrip("\n").rstrip("\r")
            if not ln:
                continue
            if ln.lstrip().startswith("#"):
                continue
            parts = ln.split("\t")
            if len(parts) < 4:
                _log("BAD_ROW (need >=4 cols): %r" % ln)
                continue
            addr_s = parts[0].strip()
            binaries = parts[1].strip()
            typ = parts[2].strip()
            name = parts[3].strip()
            desc = "\t".join(parts[4:]).strip() if len(parts) > 4 else ""
            try:
                addr_int = int(addr_s, 16)
            except ValueError:
                _log("BAD_ADDR_PARSE: %r" % addr_s)
                continue
            rows.append({
                "addr": addr_int,
                "binaries": set(b.strip() for b in binaries.split(",") if b.strip()),
                "type": typ,
                "name": name,
                "desc": desc,
            })
    finally:
        f.close()
    return rows

def _normalize_program_name(prog_name):
    # 'BATTLE.BIN' -> 'BATTLE'; 'E001.BIN' -> 'E001'; 'SCUS_942.21' -> 'SCUS'
    if prog_name.startswith("SCUS"):
        return "SCUS"
    if prog_name.endswith(".BIN"):
        return prog_name[:-4]
    return prog_name

def _row_applies(row, prog_tag):
    if "*" in row["binaries"]:
        return True
    return prog_tag in row["binaries"]

def _maybe_log_override(row):
    # Only HIGH tier logs OVERRIDE — LOW running first has nothing to override.
    if TIER != "HIGH":
        return
    addr = toAddr(row["addr"])
    sym = getSymbolAt(addr)
    if sym is None:
        return
    if sym.getSource() != SourceType.USER_DEFINED:
        return
    old = sym.getName()
    if old == row["name"]:
        return
    if row["type"] == "DEL":
        _log("OVERRIDE-DEL: 0x%08x was '%s'" % (row["addr"], old))
    else:
        _log("OVERRIDE: 0x%08x low='%s' -> high='%s'" % (row["addr"], old, row["name"]))

def _apply_fn(row):
    addr = toAddr(row["addr"])
    func = getFunctionAt(addr)
    if func is None:
        containing = getFunctionContaining(addr)
        if containing is not None:
            _log("SKIP_MID_INSTR 0x%08x inside '%s' (wanted '%s')" % (
                row["addr"], containing.getName(), row["name"]))
            return
        if not CreateFunctionCmd(addr).applyTo(currentProgram):
            _log("SKIP_NOT_CODE 0x%08x (cannot create fn '%s')" % (row["addr"], row["name"]))
            return
        func = getFunctionAt(addr)
        if func is None:
            _log("SKIP_FN_RESOLVE 0x%08x" % row["addr"])
            return
    cur = func.getName()
    if cur == row["name"]:
        return  # idempotent
    func.setName(row["name"], SourceType.USER_DEFINED)
    _log("FN 0x%08x %s -> %s" % (row["addr"], cur, row["name"]))

def _apply_gl(row):
    addr = toAddr(row["addr"])
    sym = getSymbolAt(addr)
    if sym is not None:
        if sym.getName() == row["name"]:
            return
        cur = sym.getName()
        RenameLabelCmd(sym, row["name"], SourceType.USER_DEFINED).applyTo(currentProgram)
        _log("GL 0x%08x %s -> %s" % (row["addr"], cur, row["name"]))
    else:
        createLabel(addr, row["name"], True)
        _log("GL 0x%08x (new) %s" % (row["addr"], row["name"]))

def _apply_del(row):
    addr = toAddr(row["addr"])
    sym = getSymbolAt(addr)
    if sym is None:
        return
    if sym.getSource() != SourceType.USER_DEFINED:
        return  # already default — nothing to revert
    old = sym.getName()
    func = getFunctionAt(addr)
    if func is not None:
        # Function entry: sym.delete() doesn't reliably revert the primary name.
        # Set it back to the Ghidra-default FUN_<addr> with ANALYSIS source.
        func.setName("FUN_%08x" % row["addr"], SourceType.ANALYSIS)
    else:
        sym.delete()
    _log("DEL 0x%08x (was '%s')" % (row["addr"], old))

_CONFIDENCE_PREFIX = "CONFIDENCE:"

# Ghidra's AsciiExporter writes single-byte chars; UTF-8 in plate comments
# comes out as mojibake (e.g. em-dash becomes 'â'). Map common offenders to
# ASCII before writing so re-exported disassembly stays readable.
_ASCII_FIXUPS = [
    (u"—", "--"),  # em dash
    (u"–", "-"),   # en dash
    (u"‘", "'"),   # left single quote
    (u"’", "'"),   # right single quote
    (u"“", '"'),   # left double quote
    (u"”", '"'),   # right double quote
    (u"…", "..."), # ellipsis
]

def _to_ascii(s):
    if s is None:
        return s
    if isinstance(s, str):
        try:
            s = s.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return s
    for from_ch, to_ch in _ASCII_FIXUPS:
        s = s.replace(from_ch, to_ch)
    try:
        return s.encode("ascii", "replace").decode("ascii")
    except Exception:
        return s


def _set_plate_comment(row):
    """Write a plate comment "CONFIDENCE: <TIER> — <desc>" at the row's addr.
    Preserves any pre-existing user-authored comment by prepending our
    confidence line. Idempotent — skip if existing already matches."""
    addr = toAddr(row["addr"])
    listing = currentProgram.getListing()
    desc = _to_ascii(row["desc"])
    if desc:
        ours = "%s %s -- %s" % (_CONFIDENCE_PREFIX, TIER, desc)
    else:
        ours = "%s %s" % (_CONFIDENCE_PREFIX, TIER)
    existing = listing.getComment(CodeUnit.PLATE_COMMENT, addr)
    if existing == ours:
        return  # idempotent
    if existing:
        # Keep manual comments. Replace ONLY the existing CONFIDENCE: line we
        # may have written previously.
        kept_lines = [
            ln for ln in existing.split("\n")
            if not ln.startswith(_CONFIDENCE_PREFIX)
        ]
        if kept_lines:
            text = "\n".join(kept_lines).rstrip("\n") + "\n\n" + ours
        else:
            text = ours
    else:
        text = ours
    if text == existing:
        return  # idempotent (e.g. only manual comment + our line stayed identical)
    listing.setComment(addr, CodeUnit.PLATE_COMMENT, text)
    _log("PLATE 0x%08x" % row["addr"])


def _clear_plate_comment(row):
    """For DEL rows: strip our CONFIDENCE line out of the plate comment.
    Preserves any non-CONFIDENCE lines (manual notes)."""
    addr = toAddr(row["addr"])
    listing = currentProgram.getListing()
    existing = listing.getComment(CodeUnit.PLATE_COMMENT, addr)
    if not existing:
        return
    kept = [ln for ln in existing.split("\n") if not ln.startswith(_CONFIDENCE_PREFIX)]
    new = "\n".join(kept).strip("\n")
    if new == existing:
        return
    listing.setComment(addr, CodeUnit.PLATE_COMMENT, new if new else None)


def _apply_row(row):
    _maybe_log_override(row)
    t = row["type"]
    if t == "FN":
        _apply_fn(row)
        _set_plate_comment(row)
    elif t == "GL":
        _apply_gl(row)
        _set_plate_comment(row)
    elif t == "DEL":
        _apply_del(row)
        _clear_plate_comment(row)
    else:
        _log("BAD_TYPE %r at 0x%08x" % (t, row["addr"]))

def _resolve_tsv_paths():
    """Return all TSVs to apply for this tier: the primary TSV plus any
    sibling files matching `<stem>*.tsv` in the same directory."""
    primary_dir = _os.path.dirname(TSV)
    primary_base = _os.path.basename(TSV)
    if not primary_base.endswith(".tsv"):
        return [TSV]
    stem = primary_base[:-4]   # strip ".tsv"
    pattern = _os.path.join(primary_dir, stem + "*.tsv")
    paths = sorted(_glob.glob(pattern))
    # Make sure the primary TSV comes first (defensive — glob ordering is
    # already alphabetical and stem matches the primary's prefix).
    if TSV in paths:
        paths.remove(TSV)
        paths.insert(0, TSV)
    return paths


def run():
    prog_name = currentProgram.getName()
    prog_tag = _normalize_program_name(prog_name)
    paths = _resolve_tsv_paths()
    all_rows = []
    for p in paths:
        n_before = len(all_rows)
        all_rows.extend(_parse_tsv(p))
        _log("loaded %s (%d rows)" % (_os.path.basename(p), len(all_rows) - n_before))
    matched = 0
    for row in all_rows:
        if not _row_applies(row, prog_tag):
            continue
        matched += 1
        _apply_row(row)
    _log("DONE program=%s tag=%s rows_total=%d rows_matched=%d" % (
        prog_name, prog_tag, len(all_rows), matched))
