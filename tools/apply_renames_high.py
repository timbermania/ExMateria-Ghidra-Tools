# -*- coding: utf-8 -*-
# @category FFT.Renames
# @runtime Jython
# Apply HIGH-confidence renames from renames_high.tsv to currentProgram.
# Wins on overlap with LOW (last-writer-wins; emits OVERRIDE log lines).
# Run via: analyzeHeadless ... -postScript apply_renames_high.py

import os
HERE = os.path.dirname(os.path.abspath(getSourceFile().getAbsolutePath()))
CONTENT = os.path.normpath(os.path.join(HERE, "..", "content"))
TIER = "HIGH"
TSV = os.path.join(CONTENT, "renames_high.tsv")
execfile(os.path.join(HERE, "_renames_common.py"))
run()
