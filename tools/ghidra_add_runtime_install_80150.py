# -*- coding: utf-8 -*-
# ghidra_add_runtime_install_80150.py
#
# Ghidra script that imports a RAM dump captured by
# research/lua_scripts/dump_pc_80150_function.lua and overlays it
# at RAM 0x80150A00 in the BATTLE.BIN program.
#
# WHY: PC 0x80150AEC runs `sh zero, 0x92(s0)` (the chan_92 clear that
# mutes voice 20 in protect_no_music — see
# research/effect_sound/working_documents/PARITY_AB_VOICE_20_EMULATOR_DIVERGENCE.md
# and PROTECT_VOICE_20_MIX_DROP_ROOT_CAUSE.md). BATTLE.BIN itself
# (file offset 0xE92EC, primary base 0x80067800) has 0x00000000 there
# — the bytes are written into RAM at runtime by some loader / hook
# / self-modifying-code path. We can't disassemble what we can't see;
# this script ingests the runtime snapshot so Ghidra can disassemble
# the installed function.
#
# Idempotent: removes any prior BATTLE_INSTALL_80150 overlay block
# before recreating.
#
# Usage (headless):
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H \
#       project-assets fft-ghidra \
#       -process "BATTLE.BIN" \
#       -scriptPath research/tools \
#       -postScript ghidra_add_runtime_install_80150.py
#
# Looks for the dump file at:
#   research/captures/ram_80150A00_4kb.bin     (canonical, committed)
# or, as fallback:
#   ~/.config/pcsx-redux/ram_80150A00_4kb.bin  (raw Lua-dump output)

import os
from java.io import FileInputStream

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

OVERLAY_BLOCK_NAME = "BATTLE_INSTALL_80150"
INSTALL_RAM_BASE   = 0x80150A00
INSTALL_SIZE       = 0x1000  # 4 KiB — matches the Lua dump


def find_dump_path():
    """Search known locations for the runtime dump file. First hit wins."""
    candidates = []
    # Allow override via env var.
    env_path = os.environ.get("RUNTIME_DUMP_80150")
    if env_path:
        candidates.append(env_path)
    # Canonical, committed location (preferred).
    repo_root = os.environ.get("FFT_REPO_ROOT") or os.getcwd()
    candidates.append(os.path.join(repo_root, "research", "captures", "ram_80150A00_4kb.bin"))
    # Raw Lua-dump landing site.
    home = os.environ.get("HOME") or os.path.expanduser("~")
    candidates.append(os.path.join(home, ".config", "pcsx-redux", "ram_80150A00_4kb.bin"))
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def remove_existing_overlay(prog):
    mem = prog.getMemory()
    for blk in mem.getBlocks():
        name = blk.getName()
        if name == OVERLAY_BLOCK_NAME or name.startswith(OVERLAY_BLOCK_NAME + "."):
            print("[install_80150] removing existing block: %s" % name)
            mem.removeBlock(blk, monitor)


def main():
    prog = currentProgram
    print("[install_80150] program=%s" % prog.getName())

    dump_path = find_dump_path()
    if not dump_path:
        print("[install_80150] SKIP — no runtime dump file found.")
        print("[install_80150] Capture one via:")
        print("[install_80150]   dofile('research/lua_scripts/dump_pc_80150_function.lua')")
        print("[install_80150] inside PCSX-Redux's Lua console with protect_no_music loaded.")
        return
    print("[install_80150] reading dump: %s" % dump_path)
    dump_size = os.path.getsize(dump_path)
    if dump_size < INSTALL_SIZE:
        print("[install_80150] WARN: dump is %d bytes, expected >= %d" % (dump_size, INSTALL_SIZE))

    remove_existing_overlay(prog)

    factory = prog.getAddressFactory()
    start = factory.getAddress("%x" % INSTALL_RAM_BASE)

    # createInitializedBlock(name, start, inputStream, length, monitor, overlay)
    fis = FileInputStream(dump_path)
    try:
        block = prog.getMemory().createInitializedBlock(
            OVERLAY_BLOCK_NAME,
            start,
            fis,
            INSTALL_SIZE,
            monitor,
            True,  # overlay = True
        )
    finally:
        fis.close()
    block.setRead(True)
    block.setWrite(True)   # writable to mirror runtime mutability
    block.setExecute(True)
    print("[install_80150] created overlay %s at %s..%s (from %s)" % (
        block.getName(), block.getStart(), block.getEnd(), dump_path))

    # Force-disassemble the entire overlay so Ghidra can build the
    # function graph from the runtime-installed code.
    overlay_space = block.getStart().getAddressSpace()
    ov_start = overlay_space.getAddress(INSTALL_RAM_BASE)
    ov_end   = overlay_space.getAddress(INSTALL_RAM_BASE + INSTALL_SIZE - 1)
    set_ = AddressSet(ov_start, ov_end)
    cmd = DisassembleCommand(ov_start, set_, True)
    if cmd.applyTo(prog, monitor):
        print("[install_80150] disassembled overlay region")
    else:
        print("[install_80150] disassemble FAILED: %s" % cmd.getStatusMsg())

    # Re-run auto-analysis to detect functions and XREFs in the newly
    # disassembled region.
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    aam = AutoAnalysisManager.getAnalysisManager(prog)
    aam.scheduleOneTimeAnalysis(None, None)
    aam.startAnalysis(monitor)
    print("[install_80150] auto-analysis complete")

    print("[install_80150] done — re-run export_ghidra_text.sh BATTLE.BIN to update")


main()
