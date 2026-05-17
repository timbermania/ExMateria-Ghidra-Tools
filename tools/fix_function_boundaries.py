# -*- coding: utf-8 -*-
# @category FFT.Renames
# @runtime Jython
# Fix function boundaries that Ghidra's auto-analyzer placed wrong, where
# we have validated entry points that fall mid-function. For each
# (correct_addr, name) pair: if the function containing correct_addr starts
# at a different address, remove that wrong-boundaried function and recreate
# it at correct_addr. Idempotent — skip if the function is already correct.
#
# Run via: analyzeHeadless ... -postScript fix_function_boundaries.py
#
# After this runs, rerun apply_all_renames.sh to apply the rename rows that
# were previously marked SKIP_MID_INSTR.

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd

# (correct_entry_addr, expected_final_name) — entries that hit
# SKIP_MID_INSTR in renames_high_sound.tsv.
FIXUPS = [
    (0x80012520, "play_sound"),
    (0x80015198, "per_channel_tick"),
]

prog = currentProgram
fm = prog.getFunctionManager()
prog_name = prog.getName()
print("[fix-fn-bounds] program=%s" % prog_name)

if prog_name != "SCUS_942.21":
    print("[fix-fn-bounds] skipping — fixups target SCUS only")
else:
    for addr_int, name in FIXUPS:
        addr = toAddr(addr_int)
        existing = getFunctionAt(addr)
        if existing is not None and existing.getEntryPoint().getOffset() == addr_int:
            print("[fix-fn-bounds] 0x%08x already has function entry — skip" % addr_int)
            continue

        containing = getFunctionContaining(addr)
        if containing is not None:
            wrong_entry = containing.getEntryPoint()
            wrong_name = containing.getName()
            print("[fix-fn-bounds] removing wrong-bounded function %s @ 0x%08x (contains target 0x%08x)" % (
                wrong_name, wrong_entry.getOffset(), addr_int))
            fm.removeFunction(wrong_entry)
        else:
            print("[fix-fn-bounds] no containing function at 0x%08x — proceeding" % addr_int)

        if not CreateFunctionCmd(addr).applyTo(prog):
            print("[fix-fn-bounds] FAIL: could not create function at 0x%08x" % addr_int)
            continue

        new_func = getFunctionAt(addr)
        if new_func is None:
            print("[fix-fn-bounds] FAIL: created but cannot resolve function at 0x%08x" % addr_int)
            continue

        new_func.setName(name, SourceType.USER_DEFINED)
        print("[fix-fn-bounds] OK: created+named %s @ 0x%08x" % (name, addr_int))
