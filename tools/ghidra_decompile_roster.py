# -*- coding: utf-8 -*-
# ghidra_decompile_roster.py
#
# Decompile the FORMATION/ROSTER menu overlay mounted by
# ghidra_add_roster_overlay.py (overlay space ROSTER_MENU_OVERLAY over
# BATTLE.BIN at 0x800F0000). Writes annotated C for every function in the
# overlay space, plus a focused header for the dynamically-confirmed orb/box
# anchors so the static picture can be paired with the dynamic evidence in
# FORMATION_SCREEN.md §10-11.
#
# Usage (headless, after the mount):
#   echo -e "y\ny" | /opt/ghidra/support/pyghidraRun -H \
#       project-assets fft-ghidra -process "BATTLE.BIN" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_decompile_roster.py <output.c>

import os
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

OVERLAY_NAME = "ROSTER_MENU_OVERLAY"

# VERIFIED TRUE function entries (prologue-aligned). IMPORTANT: only seed real
# entry points — force-creating a function at a MID-function address truncates
# the enclosing function's body at that point and does NOT auto-heal when the
# spurious function is later deleted (see ghidra_fix_generator_boundary.py). The
# handoff's addresses 0x80116AEC (mid orb_cell_generator) and 0x8012C8E0 (+0x24
# into the setter) are NOT entries — use the prologue addresses below.
SEED_FUNCS = {
    0x80116264: "orb_cell_generator",   # per-cell orb draw loop (incl. selected-cell pulse tail)
    0x80116DD0: "orb_spatial_falloff",  # base - sqrt(dx^2+4dy^2)/64, clamped
    0x8012C8BC: "menu_sprite_setter",   # POLY_FT4 alloc + colour/UV/OT (0x8012C8E0 = +0x24)
}

# Resident/libgpu callees named for readability (labels only; these live in
# SCUS / resident space outside this program, so calls stay external).
NOTE_ADDRS = {
    0x80023C90: "SetSemiTrans_a",
    0x80023C68: "SetSemiTrans_b",
    0x800248FC: "LoadImage",
    0x8018BAD0: "orb_center_xy",
    0x801F07D0: "scratch_orb_color",
    0x801F10D8: "orb_prim_cell0",
}


def find_overlay_space(prog):
    af = prog.getAddressFactory()
    for sp in af.getAllAddressSpaces():
        if sp.getName() == OVERLAY_NAME or sp.getName().startswith(OVERLAY_NAME):
            return sp
    return None


def main():
    prog = currentProgram
    args = getScriptArgs()
    out_path = args[0] if args else "/tmp/roster_overlay_decompile.c"

    ov = find_overlay_space(prog)
    if ov is None:
        print("[decomp] ERROR: overlay space %s not found — run ghidra_add_roster_overlay.py first" % OVERLAY_NAME)
        return
    print("[decomp] overlay space: %s (%s..%s)" % (ov.getName(), ov.getMinAddress(), ov.getMaxAddress()))

    st = prog.getSymbolTable()
    for va, name in SEED_FUNCS.items():
        a = ov.getAddress(va)
        if getFunctionAt(a) is None:
            disassemble(a)
            CreateFunctionCmd(a).applyTo(prog)
        f = getFunctionAt(a)
        if f is not None:
            f.setName(name, SourceType.USER_DEFINED)
            print("[decomp] seed fn %s @ %08x" % (name, va))
        else:
            print("[decomp] WARN could not create fn at %08x" % va)
    for va, name in NOTE_ADDRS.items():
        try:
            st.createLabel(prog.getAddressFactory().getDefaultAddressSpace().getAddress(va), name, SourceType.USER_DEFINED)
        except Exception:
            pass

    # Enumerate every function whose entry is in the overlay space.
    fm = prog.getFunctionManager()
    funcs = []
    it = fm.getFunctions(True)
    while it.hasNext():
        f = it.next()
        if f.getEntryPoint().getAddressSpace() == ov:
            funcs.append(f)
    funcs.sort(key=lambda f: f.getEntryPoint().getOffset())
    print("[decomp] %d functions in overlay space" % len(funcs))

    decomp = DecompInterface()
    decomp.setOptions(DecompileOptions())
    decomp.openProgram(prog)
    monitor = ConsoleTaskMonitor()

    lines = ["/* roster/menu overlay decompilation (mounted from live RAM @0x800F0000) */",
             "/* seeds: orb generator 0x80116AEC, falloff 0x80116DD0, setter 0x8012C8E0 */", ""]
    ok = bad = 0
    for f in funcs:
        r = decomp.decompileFunction(f, 60, monitor)
        if r and r.decompileCompleted():
            lines.append("/* ---- %s @ %s ---- */" % (f.getName(), f.getEntryPoint()))
            lines.append(r.getDecompiledFunction().getC())
            lines.append("")
            ok += 1
        else:
            lines.append("/* FAILED %s @ %s */" % (f.getName(), f.getEntryPoint()))
            bad += 1
    decomp.dispose()

    d = os.path.dirname(out_path)
    if d and not os.path.exists(d):
        os.makedirs(d)
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))
    print("[decomp] wrote %s (%d ok, %d failed)" % (out_path, ok, bad))


main()
