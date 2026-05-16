# -*- coding: utf-8 -*-
# ghidra_add_battle_secondary.py
#
# Ghidra script that adds an overlay memory block to BATTLE.BIN at the
# RAM address where the file's "tail" section actually loads at
# runtime. Verified via runtime probes (probe_dump_runtime_aa.lua):
#
#   File offset 0x142800..0x155168 of BATTLE.BIN loads at RAM
#   0x801A9800..0x801BC168 (base 0x80067000), NOT at the primary base
#   0x80067800. The OVERLAP at RAM 0x801AA000..0x801AA7FF has the
#   secondary content (overwrites primary at runtime).
#
# This is internal BATTLE.BIN segmentation, NOT an E###.BIN overlay
# (those mount at 0x801C2500).
#
# Uses Ghidra's FileBytes API to map the overlay block directly from
# the imported BATTLE.BIN file bytes (preserves source attribution and
# avoids Python<->Java byte-array conversion problems).
#
# Usage (one-shot, headless):
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H \
#       project-assets fft-ghidra \
#       -process "BATTLE.BIN" \
#       -scriptPath research/tools \
#       -postScript ghidra_add_battle_secondary.py
#
# Then re-export disassembly:
#   echo -e "y\ny" | ./research/tools/export_ghidra_text.sh --listing-only BATTLE.BIN

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

# Secondary section parameters (verified empirically):
SECONDARY_FILE_OFF  = 0x142800
SECONDARY_FILE_END  = 0x155168
SECONDARY_RAM_BASE  = 0x801A9800
SECONDARY_SIZE      = SECONDARY_FILE_END - SECONDARY_FILE_OFF  # 0x12968

OVERLAY_BLOCK_NAME = "BATTLE_SECONDARY"


def get_file_bytes(prog):
    """Return the FileBytes object that backs BATTLE.BIN's import."""
    all_fb = prog.getMemory().getAllFileBytes()
    if not all_fb:
        raise RuntimeError("no FileBytes attached to program")
    # BATTLE.BIN is a single import, so just take the first FileBytes.
    return all_fb[0]


def remove_existing_overlay(prog):
    mem = prog.getMemory()
    for blk in mem.getBlocks():
        if blk.getName() == OVERLAY_BLOCK_NAME or blk.getName().startswith(OVERLAY_BLOCK_NAME + "."):
            print("[secondary] removing existing block: %s" % blk.getName())
            mem.removeBlock(blk, monitor)


def main():
    prog = currentProgram
    print("[secondary] program=%s" % prog.getName())

    mem = prog.getMemory()
    factory = prog.getAddressFactory()
    file_bytes = get_file_bytes(prog)
    print("[secondary] using FileBytes: %s (size=%d)" % (file_bytes.getFilename(), file_bytes.getSize()))

    # Clean up any previous overlay run.
    remove_existing_overlay(prog)

    secondary_start = factory.getAddress("%x" % SECONDARY_RAM_BASE)

    # createInitializedBlock(name, start, fileBytes, fileOffset, size, overlay)
    block = mem.createInitializedBlock(
        OVERLAY_BLOCK_NAME,
        secondary_start,
        file_bytes,
        SECONDARY_FILE_OFF,
        SECONDARY_SIZE,
        True,  # overlay = True (creates a separate address space so it doesn't conflict)
    )
    block.setRead(True)
    block.setWrite(False)
    block.setExecute(True)
    print("[secondary] created overlay block %s at %s..%s (file 0x%X..0x%X)" % (
        block.getName(), block.getStart(), block.getEnd(),
        SECONDARY_FILE_OFF, SECONDARY_FILE_END - 1))

    # Disassemble the new region. Use the overlay's address space.
    overlay_space = block.getStart().getAddressSpace()
    ov_start = overlay_space.getAddress(SECONDARY_RAM_BASE)
    ov_end   = overlay_space.getAddress(SECONDARY_RAM_BASE + SECONDARY_SIZE - 1)
    set_ = AddressSet(ov_start, ov_end)
    cmd = DisassembleCommand(ov_start, set_, True)
    if cmd.applyTo(prog, monitor):
        print("[secondary] disassembled overlay region")
    else:
        print("[secondary] disassemble FAILED: %s" % cmd.getStatusMsg())

    print("[secondary] done — re-run export_ghidra_text.sh BATTLE.BIN to update")


main()
