# -*- coding: utf-8 -*-
# ghidra_list_programs.py
# Ghidra Jython postScript that emits a one-line summary of the program
# currentProgram. Used with `analyzeHeadless ... -process "*"` to enumerate
# every program in a project.
#
# Output format (one line per program, written to stdout):
#   PROG | <name> | <language_id> | <addr_min>-<addr_max> | <num_functions>
#
# Usage (from dump_full_disasm.sh):
#   analyzeHeadless <ghidra-project-dir> <project-name> \
#       -process "*" \
#       -scriptPath fft-ghidra/tools \
#       -postScript ghidra_list_programs.py \
#       -readOnly -noanalysis

prog = currentProgram
mem = prog.getMemory()
fm = prog.getFunctionManager()

name = prog.getName()
lang = prog.getLanguageID().getIdAsString()
addr_min = mem.getMinAddress()
addr_max = mem.getMaxAddress()
num_funcs = fm.getFunctionCount()

print("PROG | %s | %s | %s-%s | %d" % (name, lang, addr_min, addr_max, num_funcs))
