# -*- coding: utf-8 -*-
# ghidra_add_roster_overlay.py
#
# Ghidra script that imports the live FORMATION/ROSTER menu-overlay code region
# (captured by fft-ghidra/tools/capture_roster_overlay.sh) and overlays it at
# RAM 0x800F0000 in the BATTLE.BIN program, then force-disassembles it so
# Ghidra can build the function graph.
#
# WHY: the roster/formation "sort list" screen renders in a menu-system OVERLAY
# that FFT DMAs into RAM over BATTLE.BIN at ~0x800F0000-0x80130000. On disc
# BATTLE.BIN is 0x00 across most of that span (verified: file offset
# (VA-0x80067000) reads zeros at the orb code addresses), so the static
# battle_disassembly.txt / battle_decompilation.c CANNOT see this code. Every
# orb/box address the RE cited so far (generator 0x80116AEC, spatial falloff
# 0x80116DD0, per-sprite setter 0x8012C8E0, box builder, upload path) was
# disassembled from live RAM via capstone — no Ghidra functions, no XREFs.
# This mounts the runtime snapshot so those become first-class Ghidra
# functions with boundaries + cross-references, unblocking real static
# analysis. See research/working_documents/FORMATION_SCREEN.md §10-11 and
# /tmp/HANDOFF_formation_orb_box_evidence.md.
#
# NOTE (resolves FORMATION_SCREEN.md §0): the overlay is DMA'd ON TOP OF
# resident BATTLE.BIN code in places (e.g. 0x8012D568 / 0x800E840C hold a GTE
# 3-D mesh routine on disc but DIFFERENT bytes at runtime). The static decomp
# read the resident bytes, not the overlay that actually executes on the roster
# screen. A dedicated overlay space keeps both readable side by side.
#
# Idempotent: removes any prior ROSTER_MENU_OVERLAY block before recreating.
#
# Usage (headless):
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H \
#       project-assets fft-ghidra \
#       -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_add_roster_overlay.py
#
# Looks for the snapshot at:
#   research/captures/roster_menu_overlay_800F0000_256kb.bin   (committed)
# override with env var ROSTER_OVERLAY_DUMP.

import os
from java.io import FileInputStream

from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

OVERLAY_BLOCK_NAME = "ROSTER_MENU_OVERLAY"
OVERLAY_RAM_BASE   = 0x800F0000
OVERLAY_SIZE       = 0x40000  # 256 KiB — matches capture_roster_overlay.sh

# Dynamically-confirmed anchors (FORMATION_SCREEN.md §10.3 / §5) — labelled so
# they are easy to find in the listing after the mount.
ANCHORS = {
    0x80116AEC: "orb_brightness_generator",   # loops 8 cells, writes scratch colour 0x801F07D0
    0x80116DD0: "orb_spatial_falloff",         # max(base - sqrt(dx^2+4dy^2), floor)
    0x8012C8E0: "menu_sprite_setter",          # writes prim colour+XY, SetSemiTrans; a0=sprite id
}


def find_dump_path():
    env_path = os.environ.get("ROSTER_OVERLAY_DUMP")
    if env_path and os.path.exists(env_path):
        return env_path
    repo_root = os.environ.get("FFT_REPO_ROOT") or os.getcwd()
    cand = os.path.join(repo_root, "research", "captures",
                        "roster_menu_overlay_800F0000_256kb.bin")
    return cand if os.path.exists(cand) else None


def remove_existing_overlay(prog):
    mem = prog.getMemory()
    for blk in list(mem.getBlocks()):
        name = blk.getName()
        if name == OVERLAY_BLOCK_NAME or name.startswith(OVERLAY_BLOCK_NAME + "."):
            print("[roster_overlay] removing existing block: %s" % name)
            mem.removeBlock(blk, monitor)


def main():
    prog = currentProgram
    print("[roster_overlay] program=%s" % prog.getName())

    dump_path = find_dump_path()
    if not dump_path:
        print("[roster_overlay] SKIP — no snapshot found.")
        print("[roster_overlay] Capture one via:")
        print("[roster_overlay]   fft-ghidra/tools/capture_roster_overlay.sh")
        print("[roster_overlay] (pcsx-redux on port 8080 with SCUS94221.sstate0 loaded).")
        return
    dump_size = os.path.getsize(dump_path)
    print("[roster_overlay] reading snapshot: %s (%d bytes)" % (dump_path, dump_size))
    if dump_size < OVERLAY_SIZE:
        print("[roster_overlay] WARN: snapshot is %d bytes, expected >= %d" % (dump_size, OVERLAY_SIZE))

    remove_existing_overlay(prog)

    factory = prog.getAddressFactory()
    start = factory.getAddress("%x" % OVERLAY_RAM_BASE)

    fis = FileInputStream(dump_path)
    try:
        block = prog.getMemory().createInitializedBlock(
            OVERLAY_BLOCK_NAME,
            start,
            fis,
            OVERLAY_SIZE,
            monitor,
            True,  # overlay = True (separate space; keeps resident bytes readable)
        )
    finally:
        fis.close()
    block.setRead(True)
    block.setWrite(True)   # writable to mirror runtime mutability
    block.setExecute(True)
    print("[roster_overlay] created overlay %s at %s..%s" % (
        block.getName(), block.getStart(), block.getEnd()))

    overlay_space = block.getStart().getAddressSpace()
    ov_start = overlay_space.getAddress(OVERLAY_RAM_BASE)
    ov_end   = overlay_space.getAddress(OVERLAY_RAM_BASE + OVERLAY_SIZE - 1)
    set_ = AddressSet(ov_start, ov_end)
    cmd = DisassembleCommand(ov_start, set_, True)
    if cmd.applyTo(prog, monitor):
        print("[roster_overlay] disassembled overlay region")
    else:
        print("[roster_overlay] disassemble FAILED: %s" % cmd.getStatusMsg())

    # Label the dynamically-confirmed anchors in the overlay space so the
    # export is navigable.
    from ghidra.program.model.symbol import SourceType
    st = prog.getSymbolTable()
    for va, name in ANCHORS.items():
        try:
            a = overlay_space.getAddress(va)
            st.createLabel(a, name, SourceType.USER_DEFINED)
            print("[roster_overlay] labelled %s @ %08x" % (name, va))
        except Exception as e:
            print("[roster_overlay] label %s failed: %s" % (name, e))

    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    aam = AutoAnalysisManager.getAnalysisManager(prog)
    aam.scheduleOneTimeAnalysis(None, None)
    aam.startAnalysis(monitor)
    print("[roster_overlay] auto-analysis complete")
    print("[roster_overlay] done — the overlay space is '%s'" % block.getStart().getAddressSpace().getName())


main()
