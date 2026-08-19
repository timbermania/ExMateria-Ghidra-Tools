# -*- coding: utf-8 -*-
# ghidra_fix_generator_boundary.py
#
# Repair orb_cell_generator's function boundary (Ghidra truncated it at
# 0x80116aeb; the true body is 0x80116264..0x80116dc8 — the tail
# 0x80116aec..0x80116dc8 is the per-cell loop's selected-cell PULSE code and
# the OT setter call). Also clears the leftover 0x8012C8E0 mid-function
# fragment so menu_sprite_setter (0x8012c8bc) is whole. Then decompiles both
# cleanly.
#
# Usage:
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H project-assets fft-ghidra \
#       -process "BATTLE.BIN" -scriptPath fft-ghidra/tools \
#       -postScript ghidra_fix_generator_boundary.py <output.c>

import os
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.function import CreateFunctionCmd, DeleteFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

OVERLAY_NAME = "ROSTER_MENU_OVERLAY"
GEN_START, GEN_END = 0x80116264, 0x80116dc8
SETTER = 0x8012c8bc
SETTER_FRAG = 0x8012C8E0  # leftover mid-function seed to remove


def overlay_space(prog):
    for sp in prog.getAddressFactory().getAllAddressSpaces():
        if sp.getName().startswith(OVERLAY_NAME):
            return sp
    return None


def main():
    prog = currentProgram
    ov = overlay_space(prog)
    out = getScriptArgs()[0] if getScriptArgs() else "/tmp/gen_fixed.c"
    fm = prog.getFunctionManager()
    mon = ConsoleTaskMonitor()

    # Delete every function whose entry sits inside the generator range — AND
    # the two entry functions themselves. Root cause of the truncation: a
    # mid-function force-create (0x80116AEC / 0x8012C8E0) in an earlier pass
    # shortened the enclosing function's body to end just before it; deleting
    # the spurious function does NOT auto-restore the enclosing body, and
    # CreateFunctionCmd is a no-op on an already-existing (truncated) entry. So
    # the entry MUST be deleted and recreated to re-derive the body from flow.
    to_del = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        ep = f.getEntryPoint()
        if ep.getAddressSpace() == ov:
            off = ep.getOffset()
            if (GEN_START <= off <= GEN_END) or off in (SETTER, SETTER_FRAG):
                to_del.append(ep)
    for ep in to_del:
        DeleteFunctionCmd(ep).applyTo(prog)
        print("[fix] deleted fn @ %s" % ep)

    # Recreate the two entry functions from scratch; the flow is clean
    # fall-through so the body extends to the next function's start.
    for va, name, want_end in [(GEN_START, "orb_cell_generator", GEN_END),
                               (SETTER, "menu_sprite_setter", None)]:
        a = ov.getAddress(va)
        disassemble(a)
        CreateFunctionCmd(a).applyTo(prog)
        f = fm.getFunctionAt(a)
        if f:
            f.setName(name, SourceType.USER_DEFINED)
            end = f.getBody().getMaxAddress()
            print("[fix] %s @ %08x body_end=%s" % (name, va, end))
            # Belt-and-suspenders: if flow still under-shoots, force the body.
            if want_end is not None and end.getOffset() < want_end:
                try:
                    f.setBody(AddressSet(ov.getAddress(va), ov.getAddress(want_end)))
                    print("[fix]   forced body -> %s" % f.getBody().getMaxAddress())
                except Exception as e:
                    print("[fix]   setBody failed: %s" % e)

    # label the pulse globals for readability
    st = prog.getSymbolTable()
    for va, name in [(0x8018BA20, "roster_selected_cell_idx"),
                     (0x8018C841, "orb_pulse_phase"),
                     (0x8018C842, "orb_pulse_dir")]:
        try:
            st.createLabel(prog.getAddressFactory().getDefaultAddressSpace().getAddress(va),
                           name, SourceType.USER_DEFINED)
        except Exception:
            pass

    decomp = DecompInterface(); decomp.setOptions(DecompileOptions()); decomp.openProgram(prog)
    lines = ["/* orb_cell_generator (full, boundary-fixed) + menu_sprite_setter */", ""]
    for va in (GEN_START, SETTER):
        f = fm.getFunctionAt(ov.getAddress(va))
        r = decomp.decompileFunction(f, 180, mon)
        lines.append("/* ==== %s @ %08x ==== */" % (f.getName(), va))
        lines.append(r.getDecompiledFunction().getC() if (r and r.decompileCompleted())
                     else "/* FAILED */")
        lines.append("")
    decomp.dispose()
    with open(out, "w") as fh:
        fh.write("\n".join(lines))
    print("[fix] wrote %s" % out)


main()
