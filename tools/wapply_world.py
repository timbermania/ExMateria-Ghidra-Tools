# -*- coding: utf-8 -*-
# wapply_world.py — PyGhidra-native applier for renames_high_world.tsv onto the
# WORLD.BIN program (the Jython appliers use execfile / py2-isms that break under
# PyGhidra on Ghidra 12.1.2). Run: pyghidraRun -H project-assets fft-ghidra
#   -process WORLD.BIN -scriptPath fft-ghidra/tools -postScript wapply_world.py
import os
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.util.task import ConsoleTaskMonitor

prog = currentProgram
af = prog.getAddressFactory()
st = prog.getSymbolTable()
fm = prog.getFunctionManager()
listing = prog.getListing()
mon = ConsoleTaskMonitor()

HERE = os.path.dirname(os.path.abspath(getSourceFile().getAbsolutePath()))
TSV = os.path.normpath(os.path.join(HERE, "..", "content", "renames_high_world.tsv"))

def norm(n):
    return "WORLD" if n.endswith(".BIN") and n.startswith("WORLD") else n
tag = norm(prog.getName())
ok = 0; skip = 0
for line in open(TSV):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) < 4:
        continue
    addr_s, binary, typ, name = parts[0], parts[1], parts[2], parts[3]
    desc = parts[4] if len(parts) > 4 else ""
    if binary != tag:
        continue
    a = af.getAddress(addr_s[2:] if addr_s.startswith("0x") else addr_s)
    if a is None:
        print("BAD ADDR %s" % addr_s); skip += 1; continue
    if typ == "FN":
        fn = fm.getFunctionAt(a)
        if fn is None:
            CreateFunctionCmd(a).applyTo(prog, mon)
            fn = fm.getFunctionAt(a)
        if fn is not None:
            fn.setName(name, SourceType.USER_DEFINED)
        else:
            st.createLabel(a, name, SourceType.USER_DEFINED)
        cu = listing.getCodeUnitAt(a)
        if cu is not None and desc:
            cu.setComment(cu.PLATE_COMMENT, desc)
        ok += 1
    elif typ == "GL":
        st.createLabel(a, name, SourceType.USER_DEFINED)
        cu = listing.getCodeUnitAt(a)
        if cu is not None and desc:
            cu.setComment(cu.PRE_COMMENT, desc)
        ok += 1
    print("[%s] %s @ %s <- %s" % (typ, name, addr_s, "ok"))
print("APPLIED %d, skipped %d" % (ok, skip))
