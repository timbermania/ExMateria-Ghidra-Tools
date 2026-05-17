# -*- coding: utf-8 -*-
# @category FFT
# @runtime Jython
#
# apply_types.py -- Parse a C header file and register its struct/typedef
# definitions in currentProgram's data type manager. Replaces the manual
# "File -> Parse C Source" GUI step.
#
# Idempotent: uses REPLACE_HANDLER for conflicts, so re-running with the
# same header produces no observable change. Re-running with a modified
# header overwrites the prior definitions.
#
# Usage (headless): normally invoked via fft-ghidra/tools/apply_all_renames.sh
# as tier 5. Direct invocation:
#   analyzeHeadless <projectDir> <projectName> \
#       -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript apply_types.py \
#         "<absolute-path>/fft-ghidra/content/types_particle_emitter.h"
#
# Usage (GUI): Window -> Script Manager -> run apply_types.py and pass
# the header path when prompted (via askFile).

import os

from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import DataTypeManager

args = getScriptArgs()
if len(args) >= 1:
    header_path = args[0]
else:
    f = askFile("Select types header (.h)", "Apply")
    header_path = f.getAbsolutePath()

if not os.path.exists(header_path):
    print("ERROR: header not found: %s" % header_path)
    raise SystemExit(1)

prog = currentProgram
if prog is None:
    print("ERROR: no currentProgram")
    raise SystemExit(1)

dtm = prog.getDataTypeManager()

print("=" * 70)
print("FFT types applicator")
print("Program: %s" % prog.getName())
print("Header:  %s" % header_path)
print("=" * 70)

# Snapshot DTM names before parse so we can report the delta.
before = set()
for dt in dtm.getAllDataTypes():
    before.add(dt.getPathName())
print("DTM size before parse: %d" % len(before))

# CParserUtils.parseHeaderFiles(openTypes, filenames, includePaths,
#                               destTypes, monitor) — parses every
# declaration in the header into destTypes (here: the program's DTM).
open_types = []        # no other DTMs to resolve types from
includes   = []        # no extra include search paths
filenames  = [header_path]

results = CParserUtils.parseHeaderFiles(
    open_types, filenames, includes, dtm, monitor
)

# Report any parser messages (warnings, errors, unparseable lines).
if results is not None:
    msgs = results.getFormattedParseMessage("")
    if msgs:
        print()
        print("Parser messages:")
        for line in str(msgs).splitlines():
            if line.strip():
                print("  %s" % line)
    if not results.successful():
        print("PARSE FAILED — header was not fully consumed")

# Diff DTM names after the parse to show what landed.
after = set()
for dt in dtm.getAllDataTypes():
    after.add(dt.getPathName())
added = sorted(after - before)

print()
print("=" * 70)
print("DTM delta: added=%d  total=%d" % (len(added), len(after)))
if added:
    print()
    print("Added:")
    for name in added:
        print("  + %s" % name)
print("=" * 70)
