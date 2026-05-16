#!/usr/bin/env bash
# Apply two-tier renames (LOW first, HIGH second) to every imported program in
# the fft-ghidra Ghidra project. Re-runnable; idempotent.
#
# Usage:
#   ./apply_all_renames.sh                # all 14 default programs
#   ./apply_all_renames.sh BATTLE.BIN     # specific subset
#
# Logs to fft-ghidra/renames/run.log.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}
GHIDRA_PROJ_DIR="$REPO_ROOT/project-assets"
GHIDRA_PROJ_NAME="fft-ghidra"
SCRIPT_DIR="$REPO_ROOT/fft-ghidra/renames"
ANALYZE="${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless"

DEFAULT_PROGRAMS=(
  BATTLE.BIN
  SCUS_942.21
  E001.BIN E005.BIN E006.BIN E007.BIN E015.BIN E033.BIN
  E035.BIN E041.BIN E047.BIN E065.BIN E067.BIN E071.BIN
)

if [[ $# -gt 0 ]]; then
  PROGRAMS=( "$@" )
else
  PROGRAMS=( "${DEFAULT_PROGRAMS[@]}" )
fi

LOG="$SCRIPT_DIR/run.log"
: > "$LOG"

for prog in "${PROGRAMS[@]}"; do
  for tier in low high; do
    echo "=== $prog / $tier ===" | tee -a "$LOG"
    "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
      -process "$prog" \
      -noanalysis \
      -scriptPath "$SCRIPT_DIR" \
      -postScript "apply_renames_${tier}.py" \
      2>&1 | tee -a "$LOG" \
      | grep -E "\[(LOW|HIGH)\]|REPORT: Save|ERROR" || true
  done
done

echo
echo "=== summary ==="
grep -cE "\[LOW\] FN "  "$LOG" | awk '{print "LOW FN applied:  " $0}'
grep -cE "\[LOW\] GL "  "$LOG" | awk '{print "LOW GL applied:  " $0}'
grep -cE "\[HIGH\] FN " "$LOG" | awk '{print "HIGH FN applied: " $0}'
grep -cE "\[HIGH\] GL " "$LOG" | awk '{print "HIGH GL applied: " $0}'
grep -cE "OVERRIDE:"     "$LOG" | awk '{print "OVERRIDEs:       " $0}'
grep -cE "SKIP_"         "$LOG" | awk '{print "SKIPs:           " $0}'
echo "Full log: $LOG"
