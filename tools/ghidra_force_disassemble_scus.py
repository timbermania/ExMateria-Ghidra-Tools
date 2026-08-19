# -*- coding: utf-8 -*-
# @category FFT.Disasm
# @runtime Jython
# ghidra_force_disassemble_scus.py
#
# Ghidra Jython script that forces disassembly of byte ranges in SCUS_942.21
# that the auto-analyzer left as raw `??` data. These are real code regions
# reached only through function pointers / GTE call thunks at runtime, so the
# static auto-analyzer never followed flow into them.
#
# Symptom this fixes: the function has a symbol and even decompiles correctly
# (the decompiler disassembles on-the-fly), but `scus_disassembly.txt` shows
# its bytes as `?? 00h` because no instructions were ever committed to the
# program database. Force-D commits them so the listing is citable.
#
# Run this BEFORE apply_all_renames.sh: clearing + re-disassembling drops the
# stub function, so the rename pass must re-apply the name afterwards (same
# ordering as fix_battle_bin_disassembly.sh -> apply_all_renames.sh).
#
# Usage (headless):
#   analyzeHeadless <project_dir> fft-ghidra \
#       -process "SCUS_942.21" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_force_disassemble_scus.py
#
# Or run from Ghidra's Script Manager (CodeBrowser open on SCUS_942.21).

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

# (start, end) byte ranges. end is exclusive. Seed each at the clean function
# entry; DisassembleCommand(follow_flow=True) walks the body within the set.
# Source: contiguous `?? ` runs in scus_disassembly.txt at these entries; both
# are links in the unit-sprite projection chain
#   build_unit_sprite_svector (0x8007b96c, BATTLE)
#     -> svector_pack (0x80042b1c)          pack 3 world shorts -> SVECTOR
#     -> rotate_vector (0x8001d578)         GTE orthographic MVMVA (sf=1)
#     -> project_all_unit_sprites (0x80086b44, BATTLE)
# See research/working_documents/INSTRUCTION_TO_RENDER.md and the
# psx-unit-projection-orthographic-mvmva finding.
RANGES = [
    (0x8001D578, 0x8001D5A0),   # rotate_vector  (10 instr: lwc2/cop2 MVMVA/swc2/cfc2/jr, 0x28 bytes)
    (0x80042B1C, 0x80042B2C),   # svector_pack   (4 instr: sh a1/a2 + jr + _sh a3, 0x10 bytes)
]

# Function entries to (re)create after their bytes are disassembled, so the
# body is bound correctly and apply_all_renames can name them.
FUNC_ENTRIES = [0x8001D578, 0x80042B1C]


def force_disasm(prog, start, end):
    """Force disassembly across [start, end). Clears existing data first."""
    addr_factory = prog.getAddressFactory()
    a_start = addr_factory.getAddress("%x" % start)
    a_end   = addr_factory.getAddress("%x" % (end - 1))
    s = AddressSet(a_start, a_end)
    listing = prog.getListing()
    listing.clearCodeUnits(a_start, a_end, False)
    cmd = DisassembleCommand(a_start, s, True)
    if not cmd.applyTo(prog, monitor):
        print("[disasm] FAILED %08X..%08X: %s" % (start, end, cmd.getStatusMsg()))
        return False
    return True


def main():
    prog = currentProgram
    print("[force_disasm_scus] program=%s" % prog.getName())
    if prog.getName() not in ("SCUS_942.21", "SCUS_942.21.bin"):
        print("[force_disasm_scus] WARNING: not the SCUS program; ranges are SCUS addresses.")
    succ = 0
    fail = 0
    for (s, e) in RANGES:
        if force_disasm(prog, s, e):
            succ += 1
        else:
            fail += 1
    print("[force_disasm_scus] disasm: %d ranges ok, %d failed" % (succ, fail))

    # Bind functions over the freshly-disassembled bytes. CreateFunctionCmd is
    # a no-op if a function already covers the entry.
    addr_factory = prog.getAddressFactory()
    made = 0
    for entry in FUNC_ENTRIES:
        a = addr_factory.getAddress("%x" % entry)
        if getFunctionAt(a) is None:
            if CreateFunctionCmd(a).applyTo(prog, monitor):
                made += 1
            else:
                print("[force_disasm_scus] create-fn FAILED @ %08X" % entry)
    print("[force_disasm_scus] functions created/bound: %d" % made)
    print("[force_disasm_scus] done")


main()
