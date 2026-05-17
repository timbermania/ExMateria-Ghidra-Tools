#!/usr/bin/env bash
# Apply the full content pipeline to every imported program in the
# fft-ghidra Ghidra project. Re-runnable; idempotent.
#
# Tiers, applied in order (later wins on overlap):
#   1. LOW    renames     — content/renames_low*.tsv
#   2. HIGH   renames     — content/renames_high*.tsv  (emits OVERRIDE: vs LOW)
#   3. labels (per binary) — content/labels_<key>.tsv   (names + plate/pre cols)
#   4. comments (per binary) — content/comments_<key>.jsonl (plate/pre/post text)
#
# Usage:
#   ./apply_all_renames.sh                # all 14 default programs
#   ./apply_all_renames.sh BATTLE.BIN     # specific subset
#
# Logs to fft-ghidra/content/run.log.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}
GHIDRA_PROJ_DIR="$REPO_ROOT/project-assets"
GHIDRA_PROJ_NAME="fft-ghidra"
TOOLS_DIR="$REPO_ROOT/fft-ghidra/tools"
CONTENT_DIR="$REPO_ROOT/fft-ghidra/content"
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

LOG="$CONTENT_DIR/run.log"
: > "$LOG"

# Tier 1+2: LOW then HIGH renames (every program).
for prog in "${PROGRAMS[@]}"; do
  for tier in low high; do
    echo "=== $prog / $tier ===" | tee -a "$LOG"
    "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
      -process "$prog" \
      -noanalysis \
      -scriptPath "$TOOLS_DIR" \
      -postScript "apply_renames_${tier}.py" \
      2>&1 | tee -a "$LOG" \
      | grep -E "\[(LOW|HIGH)\]|REPORT: Save|ERROR" || true
  done
done

# Tier 3: labels (per binary). One TSV per program if present. Each TSV's
# rows must address PCs that live inside its target program's memory map —
# cross-binary rows fail silently as `fn: FAIL_CREATE` / `WARN: no code unit`.
for prog in "${PROGRAMS[@]}"; do
  case "$prog" in
    SCUS_942.21)  labels_file="$CONTENT_DIR/labels_scus.tsv" ;;
    BATTLE.BIN)   labels_file="$CONTENT_DIR/labels_battle_bin.tsv" ;;
    *)            continue ;;
  esac
  if [[ -f "$labels_file" ]]; then
    echo "=== $prog / labels ===" | tee -a "$LOG"
    "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
      -process "$prog" \
      -noanalysis \
      -scriptPath "$TOOLS_DIR" \
      -postScript "fft_apply_labels.py" "$labels_file" \
      2>&1 | tee -a "$LOG" \
      | grep -E "^0x[0-9a-fA-F]+[[:space:]]+(function|label)|Summary:|ERROR|WARN" || true
  fi
done

# Tier 4: comments (per-binary JSONL files). Add more cases below as new
# comment files are extracted from research findings.
for prog in "${PROGRAMS[@]}"; do
  case "$prog" in
    SCUS_942.21)  comments_file="$CONTENT_DIR/comments_scus.jsonl" ;;
    BATTLE.BIN)   comments_file="$CONTENT_DIR/comments_battle_bin.jsonl" ;;
    *)            continue ;;
  esac
  if [[ -f "$comments_file" ]]; then
    echo "=== $prog / comments ===" | tee -a "$LOG"
    "$ANALYZE" "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
      -process "$prog" \
      -noanalysis \
      -scriptPath "$TOOLS_DIR" \
      -postScript "apply_comments.py" "$comments_file" \
      2>&1 | tee -a "$LOG" \
      | grep -E "applied|SKIP|Summary:|ERROR" || true
  fi
done

echo
echo "=== summary ==="
grep -cE "\[LOW\] FN "                              "$LOG" | awk '{print "LOW FN applied:    " $0}'
grep -cE "\[LOW\] GL "                              "$LOG" | awk '{print "LOW GL applied:    " $0}'
grep -cE "\[HIGH\] FN "                             "$LOG" | awk '{print "HIGH FN applied:   " $0}'
grep -cE "\[HIGH\] GL "                             "$LOG" | awk '{print "HIGH GL applied:   " $0}'
grep -cE "^0x[0-9a-fA-F]+[[:space:]]+function "     "$LOG" | awk '{print "LABEL fn rows:     " $0}'
grep -cE "^0x[0-9a-fA-F]+[[:space:]]+label "        "$LOG" | awk '{print "LABEL pc rows:     " $0}'
grep -cE "^[[:space:]]+0x[0-9a-fA-F]+.*applied"     "$LOG" | awk '{print "COMMENT applied:   " $0}'
grep -cE "OVERRIDE:"                                "$LOG" | awk '{print "OVERRIDEs:         " $0}'
grep -cE "SKIP_"                                    "$LOG" | awk '{print "SKIPs:             " $0}'
echo "Full log: $LOG"
