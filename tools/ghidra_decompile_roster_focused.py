# -*- coding: utf-8 -*-
# ghidra_decompile_roster_focused.py
#
# Repair the function boundaries fragmented by the mid-function seeds in the
# first pass, then decompile the exact orb/box call chain cleanly. Run after
# ghidra_add_roster_overlay.py.
#
#   caller   FUN_80113618  (menu builder; calls generator with fp arg)
#   gen      0x80116264    (per-cell orb/marker generator; true entry)
#   setter   0x8012c8bc    (writes prim colour+XY; SetSemiTrans) [0x8012C8E0 = +0x24]
#   helpers  0x80118244, 0x80117db8, 0x80117ffc
#
# Usage:
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H project-assets fft-ghidra \
#       -process "BATTLE.BIN" -scriptPath fft-ghidra/tools \
#       -postScript ghidra_decompile_roster_focused.py <output.c>

import os
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd, DeleteFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

OVERLAY_NAME = "ROSTER_MENU_OVERLAY"
BAD_SEEDS = [0x80116AEC, 0x80116018, 0x80116C50]  # mid-function forced fns to remove
TARGETS = [
    (0x80113618, "menu_builder_calls_generator"),
    (0x80116264, "orb_cell_generator"),
    (0x8012c8bc, "menu_sprite_setter"),
    (0x80118244, "orb_sprite_emit"),
    (0x80117db8, "sprite_emit_A"),
    (0x80117ffc, "sprite_emit_B"),
]


def find_overlay_space(prog):
    for sp in prog.getAddressFactory().getAllAddressSpaces():
        if sp.getName().startswith(OVERLAY_NAME):
            return sp
    return None


def main():
    prog = currentProgram
    args = getScriptArgs()
    out_path = args[0] if args else "/tmp/roster_focused.c"
    ov = find_overlay_space(prog)
    if ov is None:
        print("[focus] ERROR overlay space not found"); return

    fm = prog.getFunctionManager()
    # 1) delete the fragmenting forced functions
    for va in BAD_SEEDS:
        a = ov.getAddress(va)
        f = fm.getFunctionAt(a)
        if f is not None:
            DeleteFunctionCmd(a).applyTo(prog)
            print("[focus] deleted fragment fn @ %08x" % va)

    # 2) (re)create the real functions
    st = prog.getSymbolTable()
    for va, name in TARGETS:
        a = ov.getAddress(va)
        if fm.getFunctionAt(a) is None:
            disassemble(a)
            CreateFunctionCmd(a).applyTo(prog)
        f = fm.getFunctionAt(a)
        if f is not None:
            f.setName(name, SourceType.USER_DEFINED)
            print("[focus] fn %s @ %08x  body=%s" % (name, va, f.getBody().getMaxAddress()))
        else:
            print("[focus] WARN no fn @ %08x" % va)

    # 3) decompile the targets
    decomp = DecompInterface(); decomp.setOptions(DecompileOptions()); decomp.openProgram(prog)
    mon = ConsoleTaskMonitor()
    lines = ["/* focused orb/box call chain — clean entries */", ""]
    for va, name in TARGETS:
        f = fm.getFunctionAt(ov.getAddress(va))
        if f is None:
            lines.append("/* MISSING %s @ %08x */\n" % (name, va)); continue
        r = decomp.decompileFunction(f, 120, mon)
        lines.append("/* ==== %s @ %08x ==== */" % (name, va))
        if r and r.decompileCompleted():
            lines.append(r.getDecompiledFunction().getC())
        else:
            lines.append("/* FAILED: %s */" % (r.getErrorMessage() if r else "null"))
        lines.append("")
    decomp.dispose()
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))
    print("[focus] wrote %s" % out_path)


main()
