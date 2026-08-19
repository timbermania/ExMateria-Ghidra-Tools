# -*- coding: utf-8 -*-
# ghidra_decompile_header.py
#
# Decompile the FORMATION/ROSTER sort-tab HEADER builder chain from the mounted
# ROSTER_MENU_OVERLAY (run ghidra_add_roster_overlay.py first). Answers: is the
# tan bar / L2-R2 buttons / active-tab highlight drawn as gouraud POLY_G4
# (vertex-coloured, no texture) or textured POLY_FT4 (and from what tpage)?
#
#   caller   0x801128e0    (calls the header builder)
#   builder  0x80112c88    (the sort-tab header — bar + 9 tab strips + highlight)
#   setter   0x8012c8bc    (shared menu_sprite_setter: writes prim colour+XY)
#
# Usage (headless):
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H project-assets fft-ghidra \
#       -process "BATTLE.BIN" -scriptPath fft-ghidra/tools \
#       -postScript ghidra_decompile_header.py <output.c>

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

OVERLAY_NAME = "ROSTER_MENU_OVERLAY"
TARGETS = [
    (0x801128e0, "header_caller"),
    (0x80112c88, "sort_tab_header_builder"),
    (0x8012c8bc, "menu_sprite_setter"),
]


def find_overlay_space(prog):
    for sp in prog.getAddressFactory().getAllAddressSpaces():
        if sp.getName().startswith(OVERLAY_NAME):
            return sp
    return None


def main():
    prog = currentProgram
    args = getScriptArgs()
    out_path = args[0] if args else "/tmp/roster_header.c"
    ov = find_overlay_space(prog)
    if ov is None:
        print("[hdr] ERROR overlay space not found (run ghidra_add_roster_overlay.py)"); return

    fm = prog.getFunctionManager()
    for va, name in TARGETS:
        a = ov.getAddress(va)
        if fm.getFunctionAt(a) is None:
            disassemble(a)
            CreateFunctionCmd(a).applyTo(prog)
        f = fm.getFunctionAt(a)
        if f is not None:
            f.setName(name, SourceType.USER_DEFINED)
            print("[hdr] fn %s @ %08x  body_end=%s" % (name, va, f.getBody().getMaxAddress()))
        else:
            print("[hdr] WARN no fn @ %08x" % va)

    decomp = DecompInterface(); decomp.setOptions(DecompileOptions()); decomp.openProgram(prog)
    mon = ConsoleTaskMonitor()
    lines = ["/* sort-tab header builder chain — from ROSTER_MENU_OVERLAY */", ""]
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
    print("[hdr] wrote %s" % out_path)


main()
