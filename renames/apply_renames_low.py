# -*- coding: utf-8 -*-
# @category FFT.Renames
# @runtime Jython
# Apply LOW-confidence renames from renames_low.tsv to currentProgram.
# Run via: analyzeHeadless ... -postScript apply_renames_low.py

import os
HERE = os.path.dirname(os.path.abspath(getSourceFile().getAbsolutePath()))
TIER = "LOW"
TSV = os.path.join(HERE, "renames_low.tsv")
execfile(os.path.join(HERE, "_renames_common.py"))
run()
