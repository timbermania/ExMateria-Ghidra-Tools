# -*- coding: utf-8 -*-
# @category FFT.Export
# @runtime Jython
# Export the current program's listing (disassembly with labels, plate
# comments, and pre-/post-comments) as plain text. Output goes to
# project-assets/fft-rom/<program>_disassembly.txt.
#
# Run: analyzeHeadless ... -process <PROGRAM> -postScript ghidra_export_listing.py

import os
from ghidra.app.util.exporter import AsciiExporter
from java.io import File

# Worktree-aware output dir. The shell wrapper export_ghidra_text.sh sets
# FFT_OUT_DIR=$REPO_ROOT/project-assets/fft-rom so each worktree exports
# into its own tree. When invoked directly via analyzeHeadless without the
# wrapper, FFT_OUT_DIR must be set in the environment.
OUT_DIR = os.environ.get("FFT_OUT_DIR")
if not OUT_DIR:
    raise RuntimeError(
        "FFT_OUT_DIR is not set. Either invoke via export_ghidra_text.sh, "
        "or export FFT_OUT_DIR=<repo>/project-assets/fft-rom before running "
        "analyzeHeadless."
    )

prog = currentProgram
name = prog.getName()
# Normalize to a clean stem: SCUS_942.21 -> scus, BATTLE.BIN -> battle, E001.BIN -> e001
stem = name.replace(".BIN", "").replace("_942.21", "").lower()

if not os.path.isdir(OUT_DIR):
    os.makedirs(OUT_DIR)

out_path = os.path.join(OUT_DIR, "%s_disassembly.txt" % stem)
fout = File(out_path)

exporter = AsciiExporter()
addr_set = prog.getMemory()  # whole program (AddressSetView)
ok = exporter.export(fout, prog, addr_set, monitor)

if ok:
    size = os.path.getsize(out_path)
    print("[export-listing] OK %s (%d bytes)" % (out_path, size))
else:
    print("[export-listing] FAIL %s" % out_path)
    log = exporter.getMessageLog()
    if log:
        print("[export-listing] log: %s" % log)
