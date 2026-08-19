# -*- coding: utf-8 -*-
# wdecomp.py — decompile the function containing each address arg + list
# callers/callees. Run under pyghidraRun -H with -process WORLD.BIN.
#   -postScript wdecomp.py 0x8010d0cc 0x80112c88 ...
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
ref = prog.getReferenceManager()
mon = ConsoleTaskMonitor()
di = DecompInterface(); di.openProgram(prog)

def A(x): return af.getAddress(x)

for arg in getScriptArgs():
    va = int(arg, 16)
    a = A("%x" % va)
    fn = fm.getFunctionContaining(a)
    print("\n================ %s ================" % arg)
    if fn is None:
        print("  (no function at %s)" % arg); continue
    ent = fn.getEntryPoint()
    print("FUNC %s @ %s  (%s .. %s)" % (fn.getName(), ent, fn.getBody().getMinAddress(), fn.getBody().getMaxAddress()))
    # callers
    callers=set()
    it = ref.getReferencesTo(ent)
    for r in it:
        c = fm.getFunctionContaining(r.getFromAddress())
        callers.add("%s@%s" % (c.getName() if c else "?", r.getFromAddress()))
    print("CALLERS(%d): %s" % (len(callers), ", ".join(sorted(callers)[:40])))
    # decompile
    res = di.decompileFunction(fn, 60, mon)
    if res and res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("  <decompile failed: %s>" % (res.getErrorMessage() if res else "null"))
