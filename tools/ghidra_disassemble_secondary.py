# -*- coding: utf-8 -*-
# ghidra_disassemble_secondary.py
#
# Runs after ghidra_add_battle_secondary.py. Force-disassembles every
# 4-byte aligned word in the BATTLE_SECONDARY overlay, then runs the
# auto-analyzer to discover functions and XREFs.

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
OVERLAY_NAME = "BATTLE_SECONDARY"
SECONDARY_RAM_BASE  = 0x801A9800
SECONDARY_SIZE      = 0x12968


def find_overlay_block(prog):
    for blk in prog.getMemory().getBlocks():
        if blk.getName() == OVERLAY_NAME and blk.isOverlay():
            return blk
    return None


def main():
    prog = currentProgram
    block = find_overlay_block(prog)
    if block is None:
        print("[disasm] no overlay block %s found — run ghidra_add_battle_secondary.py first" % OVERLAY_NAME)
        return

    overlay_space = block.getStart().getAddressSpace()
    start_a = overlay_space.getAddress(SECONDARY_RAM_BASE)
    end_a   = overlay_space.getAddress(SECONDARY_RAM_BASE + SECONDARY_SIZE - 1)

    # Iterate every 4-byte boundary and try to disassemble. Ghidra's
    # DisassembleCommand follows control flow, so most words will be
    # picked up by the first call; iterating ensures unreachable code
    # blocks (functions only called via fn-ptr tables) also get
    # disassembled.
    listing = prog.getListing()
    addr = start_a
    success_count = 0
    while addr.compareTo(end_a) <= 0:
        # Skip already-disassembled instructions.
        if listing.getInstructionAt(addr) is None:
            cu = listing.getCodeUnitAt(addr)
            if cu is not None:
                # Clear the existing data-unit so we can disassemble.
                listing.clearCodeUnits(addr, addr.add(3), False)
            cmd = DisassembleCommand(addr, AddressSet(addr, end_a), True)
            if cmd.applyTo(prog, monitor):
                success_count += 1
        addr = addr.add(4)
    print("[disasm] force-disassembled %d additional entry points" % success_count)

    # Trigger auto-analysis on the overlay region to discover function
    # entries, parameters, and XREFs.
    aam = AutoAnalysisManager.getAnalysisManager(prog)
    aam.scheduleAddressSetAnalysis(AddressSet(start_a, end_a), "DisassemblyRequest")
    aam.startAnalysis(monitor)
    print("[disasm] auto-analysis complete")


main()
