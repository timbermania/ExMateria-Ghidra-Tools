# -*- coding: utf-8 -*-
# ghidra_add_battle_overlay.py
#
# Ghidra script that adds a secondary memory block to BATTLE.BIN at
# RAM base 0x80067000, mapping the file offset 0x143000+ region to its
# actual runtime location starting at RAM 0x801AA000.
#
# Discovered via probe_dump_battle_region.lua + cross-reference:
# - Ghidra's primary BATTLE.BIN base is 0x80067800
# - Runtime confirms RAM 0x801AA008 contains the function whose bytes
#   are at BATTLE.BIN file offset 0x143008 (i.e., base 0x80067000)
# - These are TWO separate load regions of the same BATTLE.BIN file,
#   not an E###.BIN overlay (those load at 0x801C2500).
#
# Usage:
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H \
#       project-assets fft-ghidra \
#       -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_add_battle_overlay.py

from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryBlock
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
from java.io import ByteArrayInputStream

monitor = ConsoleTaskMonitor()

# Region observed at runtime: RAM 0x801AA000..0x801AC000 (8KB sample;
# actual size of the BATTLE.BIN secondary section is TBD). Source file
# offset = RAM - 0x80067000.
OVERLAY_RAM_BASE = 0x801AA000
OVERLAY_SIZE     = 0x2000        # 8KB to start
OVERLAY_FILE_OFF = OVERLAY_RAM_BASE - 0x80067000   # = 0x143000


def read_file_bytes(prog, off, size):
    """Read raw bytes from BATTLE.BIN file via the FileBytes loader."""
    # In Ghidra, the program's underlying ImportedFile is accessible.
    # However a simpler approach: read from the existing primary memory
    # block at RAM 0x80067000 + off — that's what Ghidra has already
    # loaded.
    mem = prog.getMemory()
    addr_factory = prog.getAddressFactory()
    start = addr_factory.getAddress("%x" % (0x80067000 + off))
    buf = bytearray(size)
    bytes_read = mem.getBytes(start, buf, 0, size)
    if bytes_read != size:
        print("[overlay] WARNING: only read %d/%d bytes from file off 0x%X" % (bytes_read, size, off))
    return bytes(buf)


def main():
    prog = currentProgram
    print("[overlay] program=%s" % prog.getName())

    mem = prog.getMemory()
    addr_factory = prog.getAddressFactory()
    start_addr = addr_factory.getAddress("%x" % OVERLAY_RAM_BASE)
    end_addr   = addr_factory.getAddress("%x" % (OVERLAY_RAM_BASE + OVERLAY_SIZE - 1))

    # Check if a block already exists.
    existing = mem.getBlock(start_addr)
    if existing is not None:
        print("[overlay] block at 0x%08X already exists: %s (size 0x%X)" % (
            OVERLAY_RAM_BASE, existing.getName(), existing.getSize()))
        # Optionally delete the existing one. For safety, abort.
        print("[overlay] not overwriting; remove the existing block manually if needed.")
        return

    # Read the source bytes from the existing primary block at RAM
    # 0x80067000 + 0x143000 = 0x801AA000... wait that's the SAME RAM
    # address. We need to read bytes that Ghidra has at file offset
    # 0x143000, which is currently mapped to RAM 0x801AA800 (file off
    # 0x143000 with base 0x80067800).
    src_addr = addr_factory.getAddress("%x" % (0x80067800 + OVERLAY_FILE_OFF))
    buf = bytearray(OVERLAY_SIZE)
    bytes_read = mem.getBytes(src_addr, buf, 0, OVERLAY_SIZE)
    print("[overlay] read %d bytes from primary block @ 0x%08X" % (bytes_read, 0x80067800 + OVERLAY_FILE_OFF))

    # Create the new memory block as an overlay (or in main RAM if no
    # conflict). Use createInitializedBlock with the byte array.
    block = mem.createInitializedBlock(
        "BATTLE_OVERLAY_AA",       # name
        start_addr,                # start
        ByteArrayInputStream(bytes(buf)),  # data
        OVERLAY_SIZE,              # size
        monitor,                   # monitor
        True,                      # overlay (True so it doesn't conflict)
    )
    block.setRead(True)
    block.setWrite(False)
    block.setExecute(True)
    print("[overlay] created block %s at 0x%08X..0x%08X (overlay=%s)" % (
        block.getName(), OVERLAY_RAM_BASE, OVERLAY_RAM_BASE + OVERLAY_SIZE - 1, block.isOverlay()))

    # Force disassembly of the overlay region.
    set_ = AddressSet(block.getStart(), block.getEnd())
    cmd = DisassembleCommand(block.getStart(), set_, True)
    if cmd.applyTo(prog, monitor):
        print("[overlay] disassembled overlay region")
    else:
        print("[overlay] disassemble FAILED: %s" % cmd.getStatusMsg())


main()
