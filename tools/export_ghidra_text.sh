#!/usr/bin/env bash
# Regenerate project-assets/fft-rom/{scus,battle}_disassembly.txt and
# {scus,battle}_decompilation.c from the current state of the fft-ghidra
# Ghidra project. Output is gitignored.
#
# Usage:
#   ./export_ghidra_text.sh                    # listings + decompilation, both programs
#   ./export_ghidra_text.sh --listing-only     # just disassembly (fast)
#   ./export_ghidra_text.sh BATTLE.BIN         # specific program(s) only
#
# Decompilation is slow — 20-40 minutes for BATTLE.BIN. Run in a separate
# terminal or with `--listing-only` first if you want quick turnaround.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}
GHIDRA_PROJ_DIR="$REPO_ROOT/project-assets"
GHIDRA_PROJ_NAME="fft-ghidra"
TOOLS_DIR="$REPO_ROOT/fft-ghidra/tools"
ANALYZE="${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless"
# The Python export scripts read FFT_OUT_DIR to decide where to write.
export FFT_OUT_DIR="$REPO_ROOT/project-assets/fft-rom"

# Map a Ghidra program name to the stem used in the export filenames
# (e.g. SCUS_942.21 -> scus, BATTLE.BIN -> battle). Matches the rule in
# ghidra_export_listing.py.
prog_to_stem() {
  local n="$1"
  n="${n%.BIN}"
  n="${n/_942.21/}"
  echo "${n,,}"
}

LISTING_ONLY=0
PROGRAMS=()
for arg in "$@"; do
  case "$arg" in
    --listing-only) LISTING_ONLY=1 ;;
    *) PROGRAMS+=("$arg") ;;
  esac
done

if [[ ${#PROGRAMS[@]} -eq 0 ]]; then
  PROGRAMS=( SCUS_942.21 BATTLE.BIN )
fi

LOG="$TOOLS_DIR/export.log"
: > "$LOG"

for prog in "${PROGRAMS[@]}"; do
  echo "=== $prog: listing ===" | tee -a "$LOG"
  "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
    -process "$prog" -noanalysis -readOnly \
    -scriptPath "$TOOLS_DIR" \
    -postScript ghidra_export_listing.py \
    2>&1 | tee -a "$LOG" \
    | grep -E "export-listing|ERROR" || true

  if [[ "$LISTING_ONLY" -eq 0 ]]; then
    stem="$(prog_to_stem "$prog")"
    echo "=== $prog: decompilation (stem=$stem) ===" | tee -a "$LOG"
    "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
      -process "$prog" -noanalysis -readOnly \
      -scriptPath "$TOOLS_DIR" \
      -postScript ghidra_full_decompile.py "$FFT_OUT_DIR" "$stem" \
      2>&1 | tee -a "$LOG" \
      | grep -E "Wrote|DONE:|ERROR" || true
    # ghidra_full_decompile.py writes <FFT_OUT_DIR>/<stem>/all_functions.c
    # plus per-function .c files + manifest.tsv + data_segments.txt.
    # Mirror the concatenated file to the canonical <stem>_decompilation.c
    # path expected by docs / callers.
    if [[ -f "$FFT_OUT_DIR/$stem/all_functions.c" ]]; then
      cp "$FFT_OUT_DIR/$stem/all_functions.c" "$FFT_OUT_DIR/${stem}_decompilation.c"
      echo "mirrored $stem/all_functions.c -> ${stem}_decompilation.c" | tee -a "$LOG"
    fi
  fi
done

# Re-annotate the LEGACY battle_bin_disassembly.txt (preserves the line
# numbers cited in older docs while picking up current renames). No-op if
# the .orig pristine source isn't present.
if [[ -f "$FFT_OUT_DIR/battle_bin_disassembly.txt.orig" ]]; then
  echo "=== legacy disassembly: re-annotate ===" | tee -a "$LOG"
  python3 "$TOOLS_DIR/annotate_legacy_disassembly.py" 2>&1 | tee -a "$LOG"
fi

echo
echo "=== summary ==="
ls -la "$FFT_OUT_DIR"/*_disassembly.txt 2>/dev/null || true
ls -la "$FFT_OUT_DIR"/*_decompilation.c 2>/dev/null || true
echo "Full log: $LOG"
