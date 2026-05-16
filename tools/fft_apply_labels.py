# -*- coding: utf-8 -*-
# fft_apply_labels.py
# Ghidra Jython postScript: apply probe-confirmed function names and
# annotations to BATTLE.BIN.
#
# Source of truth: research/ghidra_labels/fft_battle_bin.tsv. Every entry
# corresponds to a probe whose value-level output pairs bit-exactly between
# PCSX-Redux and Godot (per research/effect_alignment/last_run/probe_pairs.json),
# so the FFT-side semantics described in each plate comment are confirmed.
#
# Idempotent: running twice is a no-op (skips functions already at the target
# name, skips comments already matching).
#
# Usage (headless):
#   analyzeHeadless <projectDir> <projectName> \
#       -process "BATTLE.BIN" \
#       -scriptPath research/scripts/ghidra \
#       -postScript fft_apply_labels.py \
#         "C:/path/to/research/ghidra_labels/fft_battle_bin.tsv" \
#       -readOnly
#
# Usage (GUI): Window → Script Manager → run fft_apply_labels.py and pass
# the absolute path to fft_battle_bin.tsv when prompted (via askFile).
#
# @category FFT
# @runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressFactory

import os
import sys

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------

args = getScriptArgs()
if len(args) >= 1:
    tsv_path = args[0]
else:
    f = askFile("Select fft_battle_bin.tsv", "Apply")
    tsv_path = f.getAbsolutePath()

if not os.path.exists(tsv_path):
    print("ERROR: TSV not found: %s" % tsv_path)
    raise SystemExit(1)

prog = currentProgram
if prog is None:
    print("ERROR: no currentProgram")
    raise SystemExit(1)

print("=" * 70)
print("FFT label applicator")
print("Program: %s" % prog.getName())
print("TSV:     %s" % tsv_path)
print("=" * 70)

af = prog.getAddressFactory()
fm = prog.getFunctionManager()
listing = prog.getListing()
symtab = prog.getSymbolTable()

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def addr(hex_str):
    """Parse '0x80014660' or '80014660' into a Ghidra Address."""
    s = hex_str.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return af.getAddress(s)


def expand_newlines(s):
    """TSV cell uses literal \\n for newlines (TSV can't carry real newlines)."""
    return s.replace("\\n", "\n")


def set_comment(a, comment_type, text):
    """Set comment_type comment at address `a`. Returns True if changed."""
    cu = listing.getCodeUnitAt(a)
    if cu is None:
        # No code unit at this exact address — try the containing one.
        cu = listing.getCodeUnitContaining(a)
        if cu is None:
            print("  WARN: no code unit at %s — comment skipped" % a)
            return False
    existing = cu.getComment(comment_type)
    if existing == text:
        return False
    cu.setComment(comment_type, text)
    return True


def rename_function(a, new_name, plate_comment):
    """Rename function at `a`; create one if it doesn't exist. Returns status string."""
    func = fm.getFunctionAt(a)
    if func is None:
        # Try to create. createFunction is a builtin in postScripts.
        try:
            func = createFunction(a, new_name)
            if func is None:
                return "FAIL_CREATE"
        except Exception as e:
            print("  WARN: createFunction(%s, %s) raised: %s" % (a, new_name, e))
            return "FAIL_CREATE"
        # Plate comment is set below.
        if plate_comment:
            set_comment(a, CodeUnit.PLATE_COMMENT, plate_comment)
        return "CREATED"

    current = func.getName()
    if current == new_name:
        # Already at target name — only refresh plate comment.
        if plate_comment and set_comment(a, CodeUnit.PLATE_COMMENT, plate_comment):
            return "REFRESHED_PLATE"
        return "NOOP"

    try:
        func.setName(new_name, SourceType.USER_DEFINED)
    except Exception as e:
        print("  WARN: setName(%s -> %s) raised: %s" % (current, new_name, e))
        return "FAIL_RENAME"
    if plate_comment:
        set_comment(a, CodeUnit.PLATE_COMMENT, plate_comment)
    return "RENAMED (from %s)" % current


def create_or_keep_label(a, label_name):
    """Ensure a primary user-defined label `label_name` exists at `a`."""
    syms = symtab.getSymbols(a)
    for s in syms:
        if s.getName() == label_name:
            return "NOOP"
    try:
        createLabel(a, label_name, True)  # makePrimary=True
        return "LABEL_CREATED"
    except Exception as e:
        print("  WARN: createLabel(%s, %s) raised: %s" % (a, label_name, e))
        return "FAIL_LABEL"


# -----------------------------------------------------------------------------
# Parse TSV
# -----------------------------------------------------------------------------

entries = []
with open(tsv_path, "r") as fh:
    header = None
    for raw in fh:
        line = raw.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if header is None:
            header = parts
            continue
        if len(parts) < 4:
            print("  SKIP malformed: %r" % line[:80])
            continue
        # Pad to 6 columns — TSV rows often omit trailing empty cells.
        while len(parts) < 6:
            parts.append("")
        entries.append({
            "pc":            parts[0].strip(),
            "kind":          parts[1].strip(),
            "name":          parts[2].strip(),
            "pair_status":   parts[3].strip(),
            "plate_comment": expand_newlines(parts[4]),
            "pre_comment":   expand_newlines(parts[5]),
        })

print("Loaded %d label entries from TSV.\n" % len(entries))

# -----------------------------------------------------------------------------
# Apply
# -----------------------------------------------------------------------------

stats = {"function": {"NOOP": 0, "RENAMED": 0, "CREATED": 0, "REFRESHED_PLATE": 0, "FAIL": 0},
         "label": {"NOOP": 0, "LABEL_CREATED": 0, "FAIL": 0},
         "pre_comment": {"SET": 0, "UNCHANGED": 0, "SKIP": 0}}

for e in entries:
    a = addr(e["pc"])
    name = e["name"]
    kind = e["kind"]
    status_tag = "[%s]" % e["pair_status"] if e["pair_status"] else ""
    print("%s  %s  %-40s  %s" % (e["pc"], kind, name, status_tag))

    if kind == "function":
        plate = e["plate_comment"]
        if plate:
            # Prepend pair status into the plate so it's visible in Ghidra
            plate = ("PAIR STATUS: %s\n%s" % (e["pair_status"], plate)) if e["pair_status"] else plate
        r = rename_function(a, name, plate)
        bucket = "FAIL" if r.startswith("FAIL") else r.split(" ", 1)[0]
        stats["function"][bucket] = stats["function"].get(bucket, 0) + 1
        print("  fn: %s" % r)
    elif kind == "label":
        r = create_or_keep_label(a, name)
        bucket = "FAIL" if r.startswith("FAIL") else r
        stats["label"][bucket] = stats["label"].get(bucket, 0) + 1
        print("  label: %s" % r)
    else:
        print("  SKIP unknown kind '%s'" % kind)

    if e["pre_comment"] and e["pre_comment"] != "-":
        text = ("[%s] %s" % (e["pair_status"], e["pre_comment"])) if e["pair_status"] else e["pre_comment"]
        changed = set_comment(a, CodeUnit.PRE_COMMENT, text)
        if changed is True:
            stats["pre_comment"]["SET"] += 1
            print("  pre_comment: SET")
        elif changed is False:
            stats["pre_comment"]["UNCHANGED"] += 1
            print("  pre_comment: UNCHANGED")
        else:
            stats["pre_comment"]["SKIP"] += 1

print()
print("=" * 70)
print("Summary:")
for cat, counts in stats.items():
    print("  %s: %s" % (cat, counts))
print("=" * 70)
