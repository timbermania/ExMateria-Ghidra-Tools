# -*- coding: utf-8 -*-
# Verify FFT program imports — dump bytes at known landmarks and force disasm.
# Used as -postScript by analyzeHeadless after import & auto-analysis.
# Landmarks come from research/key_documents/MEMORY_LAYOUT_REFERENCE.md
# @category FFT
# @runtime Jython

from ghidra.app.cmd.disassemble import DisassembleCommand

prog = currentProgram
name = prog.getName()
mem  = prog.getMemory()
listing = prog.getListing()
af = prog.getAddressFactory()

LANDMARKS = {
    "SCUS_942.21": (0x80010000, "00 70 06 80"),  # main exec start, undefined4 0x80067000
    "BATTLE.BIN":  (0x801A5B4C, "00 58 04 34"),  # particle spawn fn entry: ori a0,zero,0x5800
                                                  # (file offset 0x13EB4C at base 0x80067000)
}

addr_int = None
expected = None
if name in LANDMARKS:
    addr_int, expected = LANDMARKS[name]
elif name.startswith("E") and (name.endswith(".BIN") or name.endswith("BIN")):
    addr_int = 0x801C2500   # all E### files load here (only one resident at a time)
    expected = None         # per-file content varies; just dump

if addr_int is None:
    print("[fft-verify] no landmark for '%s' -- skipping" % name)
else:
    addr = af.getAddress("0x%x" % addr_int)
    block = mem.getBlock(addr)
    if block is None:
        print("[fft-verify] FAIL %s: no memory block at 0x%08x (wrong base address?)" % (name, addr_int))
    else:
        bs = []
        for i in range(16):
            try:
                bs.append(mem.getByte(addr.add(i)) & 0xff)
            except:
                bs.append(None)
        actual = " ".join(("%02x" % b) if b is not None else "??" for b in bs)
        verdict = ""
        if expected is not None:
            verdict = " -- %s" % ("OK" if actual.startswith(expected) else ("MISMATCH (expected " + expected + ")"))
        print("[fft-verify] %-16s @ 0x%08x: %s%s" % (name, addr_int, actual, verdict))

        # Force disassembly at the landmark so we can confirm processor/endian look right.
        ins = listing.getInstructionAt(addr)
        if ins is None:
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(prog)
            ins = listing.getInstructionAt(addr)
        if ins is not None:
            print("[fft-verify]   disasm: %s" % ins)
        else:
            print("[fft-verify]   could not disassemble at 0x%08x" % addr_int)

        # Memory map summary (helpful diagnostic)
        blocks = mem.getBlocks()
        print("[fft-verify]   blocks: %s" % ", ".join(
            "%s[0x%x-0x%x]" % (b.getName(), b.getStart().getOffset(), b.getEnd().getOffset())
            for b in blocks
        ))
