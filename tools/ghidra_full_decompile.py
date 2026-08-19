# -*- coding: utf-8 -*-
# @category FFT.Export
# @runtime Jython
# ghidra_full_decompile.py
# Ghidra Jython postScript that decompiles every function in currentProgram
# and emits a structured dump on disk:
#
#   <output_root>/<prog_name>/
#       functions/<funcname>__<addr>.c     # one C file per function
#       all_functions.c                    # concatenated, sorted by address
#       data_segments.txt                  # data sections (globals, jump tables)
#       manifest.tsv                       # addr  name  size  callers  callees
#
# Usage (from dump_full_disasm.sh, headless):
#   analyzeHeadless <ghidra-project-dir> <project-name> \
#       -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_full_decompile.py \
#         "<absolute-path-to>/research/effect_sound/ghidra_dump" \
#         "BATTLE_BIN" \
#       -readOnly -noanalysis
#
# Args:
#   args[0] -- output root directory (absolute path)
#   args[1] -- subdirectory name to use under output_root (e.g. "BATTLE_BIN", "SCUS")

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType, SourceType

import codecs
import os
import re

# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------

args = getScriptArgs()
if len(args) < 2:
    print("ERROR: expected 2 args (output_root, subdir_name)")
    print("Got: %s" % str(args))
    raise SystemExit(1)

output_root = args[0]
subdir_name = args[1]

prog_dir = os.path.join(output_root, subdir_name)
fn_dir = os.path.join(prog_dir, "functions")

for d in (output_root, prog_dir, fn_dir):
    if not os.path.isdir(d):
        os.makedirs(d)

print("=" * 70)
print("FFT Effect-Sound Full Decompile")
print("Program: %s" % currentProgram.getName())
print("Output:  %s" % prog_dir)
print("=" * 70)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

_INVALID_FN_CHARS = re.compile(r"[^A-Za-z0-9_.\-]")


def safe_filename(name):
    """Make a function name safe for use in a filename."""
    s = _INVALID_FN_CHARS.sub("_", name)
    if len(s) > 80:
        s = s[:80]
    return s or "unnamed"


def callers_of(func):
    """Return set of caller function entry-point hex strings (or 'EXTERNAL')."""
    out = set()
    for f in func.getCallingFunctions(monitor):
        out.add("0x%08X" % f.getEntryPoint().getOffset())
    return sorted(out)


def callees_of(func):
    """Return set of callee function entry-point hex strings."""
    out = set()
    for f in func.getCalledFunctions(monitor):
        out.add("0x%08X" % f.getEntryPoint().getOffset())
    return sorted(out)


def function_size_bytes(func):
    body = func.getBody()
    return body.getNumAddresses() if body else 0


# -----------------------------------------------------------------------------
# Step 1 — collect all functions, sort by address
# -----------------------------------------------------------------------------

monitor = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()
all_funcs = []

it = fm.getFunctions(True)
while it.hasNext():
    f = it.next()
    if f.isThunk():
        # Still include thunks but mark them
        pass
    all_funcs.append(f)

all_funcs.sort(key=lambda f: f.getEntryPoint().getOffset())
print("\nFound %d functions" % len(all_funcs))

# -----------------------------------------------------------------------------
# Step 2 — set up decompiler
# -----------------------------------------------------------------------------

decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(currentProgram)

# -----------------------------------------------------------------------------
# Step 3 — decompile each function, write per-function files, accumulate all_funcs
# -----------------------------------------------------------------------------

manifest_rows = []  # list of (addr_int, name, size, n_callers, n_callees)
all_lines = [
    "/*",
    " * Auto-decompiled by ghidra_full_decompile.py",
    " * Program: %s" % currentProgram.getName(),
    " * Functions: %d" % len(all_funcs),
    " */",
    "",
]

success = 0
fail = 0

# Track filename collisions (same canonical name at different addresses).
seen_filenames = {}

for i, func in enumerate(all_funcs):
    addr = func.getEntryPoint()
    addr_int = addr.getOffset()
    name = func.getName()
    size = function_size_bytes(func)
    n_call_in = len(callers_of(func))
    n_call_out = len(callees_of(func))

    if i % 50 == 0:
        print("  [%d/%d] %s @ %s" % (i, len(all_funcs), name, addr))

    # Per-function file
    base = "%s__%08X" % (safe_filename(name), addr_int)
    if base in seen_filenames:
        # extra-safe collision suffix (shouldn't happen — addr is unique)
        base = "%s_dup%d" % (base, seen_filenames[base])
        seen_filenames[base] = seen_filenames.get(base, 0) + 1
    else:
        seen_filenames[base] = 1
    fn_path = os.path.join(fn_dir, base + ".c")

    # Decompile
    result = decomp.decompileFunction(func, 60, monitor)

    header = [
        "/* ============================================================",
        " *  Function: %s" % name,
        " *  Address:  0x%08X  (size 0x%X bytes)" % (addr_int, size),
        " *  Callers:  %s" % (", ".join(callers_of(func)) or "(none)"),
        " *  Callees:  %s" % (", ".join(callees_of(func)) or "(none)"),
        " * ============================================================ */",
        "",
    ]

    if result and result.decompileCompleted():
        c_code = result.getDecompiledFunction().getC()
        body = "\n".join(header) + c_code
        success += 1
    else:
        err = result.getErrorMessage() if result else "null result"
        body = "\n".join(header) + "/* FAILED to decompile: %s */\n" % err
        fail += 1

    f_out = codecs.open(fn_path, "w", encoding="utf-8")
    try:
        f_out.write(body)
    finally:
        f_out.close()

    # Append to all_functions.c
    all_lines.append("/* ---- %s @ 0x%08X ---- */" % (name, addr_int))
    all_lines.append(body)
    all_lines.append("")

    manifest_rows.append((addr_int, name, size, n_call_in, n_call_out))

decomp.dispose()

# -----------------------------------------------------------------------------
# Step 4 — write all_functions.c
# -----------------------------------------------------------------------------

all_path = os.path.join(prog_dir, "all_functions.c")
f_out = codecs.open(all_path, "w", encoding="utf-8")
try:
    f_out.write("\n".join(all_lines))
finally:
    f_out.close()
print("Wrote %s (%d lines)" % (all_path, len(all_lines)))

# -----------------------------------------------------------------------------
# Step 5 — manifest.tsv
# -----------------------------------------------------------------------------

manifest_path = os.path.join(prog_dir, "manifest.tsv")
f_out = open(manifest_path, "w")
try:
    f_out.write("address\tname\tsize_bytes\tnum_callers\tnum_callees\n")
    for addr_int, name, size, ci, co in manifest_rows:
        f_out.write("0x%08X\t%s\t%d\t%d\t%d\n" % (addr_int, name, size, ci, co))
finally:
    f_out.close()
print("Wrote %s" % manifest_path)

# -----------------------------------------------------------------------------
# Step 6 — data_segments.txt: dump non-default labeled symbols (globals)
# -----------------------------------------------------------------------------

ds_path = os.path.join(prog_dir, "data_segments.txt")
f_out = open(ds_path, "w")
try:
    f_out.write("# Labeled data symbols in %s\n" % currentProgram.getName())
    f_out.write("# Address\tType\tName\n")

    st = currentProgram.getSymbolTable()
    sym_iter = st.getAllSymbols(True)
    rows = []
    for sym in sym_iter:
        # Only USER_DEFINED, IMPORTED, and DEFAULT-but-named global labels.
        if sym.getSymbolType() == SymbolType.LABEL:
            src = sym.getSource()
            if src in (SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.ANALYSIS):
                rows.append((sym.getAddress().getOffset(), "label", sym.getName()))
    rows.sort(key=lambda r: r[0])
    for addr_int, kind, name in rows:
        f_out.write("0x%08X\t%s\t%s\n" % (addr_int, kind, name))
finally:
    f_out.close()
print("Wrote %s (%d symbols)" % (ds_path, len(rows)))

print("=" * 70)
print("DONE: %d succeeded, %d failed" % (success, fail))
print("=" * 70)
