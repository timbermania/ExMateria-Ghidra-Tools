# -*- coding: utf-8 -*-
# ghidra_force_disassemble_battle.py
#
# Ghidra Jython script that forces disassembly of byte ranges in BATTLE.BIN
# that the auto-analyzer missed. These are real code regions called via
# jal/jalr at runtime (verified by runtime byte-decoding probes in
# research/effect_alignment/probes/probe_decode_caller_bytes.lua).
#
# Then re-runs auto-analysis to detect functions and XREFs.
#
# Usage (headless):
#   analyzeHeadless <project_dir> fft-ghidra \
#       -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_force_disassemble_battle.py
#
# Or run from Ghidra's Script Manager (CodeBrowser open on BATTLE.BIN).
#
# Background:
# probe_decode_caller_bytes.lua read RAM at 0x801AA09C at runtime and found
# `jal 0x801A522C` (0x0C06948B) — but Ghidra's static disassembly shows
# bytes there as raw `??` data. The auto-analyzer didn't recognize the
# code. This affects FUN_801A51BC's actual call-flow analysis (its mid-
# function entry from 0x801AA09C isn't tracked as an XREF in Ghidra).
#
# Affected ranges (from grep of `^ram:801a[a9]... ?? ` in battle_disassembly.txt):

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

# Byte ranges Ghidra failed to disassemble. Source: grep raw-byte rows in
# battle_disassembly.txt for 0x801A9000..0x801AC000 and merge contiguous.
RANGES = [
    # Vitals-readout (HP/MP/CT bars) draw page. The whole 0x80135xxx page was
    # left as ?? raw data by the auto-analyzer, hiding the bar renderer
    # FUN_801352bc @ 0x801352BC (reached via jal from 0x8013608C/0x80135A98).
    # Recovered live (capstone) in the 2026-06-19 vitals-bar RE pass; see
    # godot-learning/docs/vitals-bar-investigation.md. Force-D the page so the
    # function lands in battle_disassembly.txt + gets a CreateFunction in the
    # auto-analysis re-run below (so it's statically citable, not ?? bytes).
    # Seed at the verified function entry (clean prologue addiu sp,-0x118) and
    # bound generously; DisassembleCommand(follow_flow=True) walks the function.
    (0x801352BC, 0x80135E00),
    (0x801A9098, 0x801A90AC),
    (0x801A9214, 0x801A926C),
    (0x801A93B0, 0x801A93B8),
    (0x801A93E0, 0x801A93EC),
    (0x801A93F8, 0x801A9414),
    (0x801A9448, 0x801A9454),
    (0x801A945C, 0x801A948C),
    (0x801A94C0, 0x801A94D4),
    (0x801A94E8, 0x801A9504),
    (0x801A9538, 0x801A957C),
    (0x801A95B0, 0x801A95E8),
    (0x801A962C, 0x801A9640),
    (0x801A9648, 0x801A96C8),
    (0x801A9714, 0x801A9720),
    (0x801A9994, 0x801A99AC),
    (0x801A9A90, 0x801A9AE0),
    (0x801A9B70, 0x801A9BB0),
    (0x801A9BB8, 0x801A9D14),
    (0x801A9EC8, 0x801A9F08),
    (0x801A9FE8, 0x801AA008),
    (0x801AA034, 0x801AA0E8),
    (0x801AA104, 0x801AA150),
    (0x801AA1AC, 0x801AA1F8),
    (0x801AA224, 0x801AA244),
    (0x801AA254, 0x801AA3A8),
    (0x801AA758, 0x801AA77C),
    (0x801AA9A0, 0x801AA9F8),
    (0x801AACE8, 0x801AAD3C),
    (0x801AAD54, 0x801AAD98),
    (0x801AAE68, 0x801AAEC8),
    (0x801AAED4, 0x801AAF24),
    (0x801AAFC4, 0x801AAFDC),
    (0x801AB3BC, 0x801AB428),
    (0x801AB454, 0x801AB530),
]


def force_disasm(prog, start, end):
    """Force disassembly across [start, end). Clears existing data first."""
    addr_factory = prog.getAddressFactory()
    a_start = addr_factory.getAddress("%x" % start)
    a_end   = addr_factory.getAddress("%x" % (end - 1))
    s = AddressSet(a_start, a_end)
    # Clear data definitions so DisassembleCommand can run.
    listing = prog.getListing()
    listing.clearCodeUnits(a_start, a_end, False)
    cmd = DisassembleCommand(a_start, s, True)
    if not cmd.applyTo(prog, monitor):
        print("[disasm] FAILED %08X..%08X: %s" % (start, end, cmd.getStatusMsg()))
        return False
    return True


def main():
    prog = currentProgram
    print("[force_disasm] program=%s" % prog.getName())
    succ = 0
    fail = 0
    for (s, e) in RANGES:
        if force_disasm(prog, s, e):
            succ += 1
        else:
            fail += 1
    print("[force_disasm] done: %d ranges disassembled, %d failed" % (succ, fail))
    # Re-run auto-analysis to discover functions and XREFs in the newly
    # disassembled code.
    from ghidra.app.script import GhidraScript
    print("[force_disasm] triggering auto-analysis re-run...")
    # In headless mode the AutoAnalysisManager handles this.
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    aam = AutoAnalysisManager.getAnalysisManager(prog)
    aam.scheduleOneTimeAnalysis(None, None)
    aam.startAnalysis(monitor)
    print("[force_disasm] auto-analysis complete")


main()
