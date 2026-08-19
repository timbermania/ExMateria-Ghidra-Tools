#!/usr/bin/env bash
# rebuild_ghidra_from_iso.sh — full scripted pipeline from raw ISO to
# current-state Ghidra disassembly. Wraps the 4 existing scripts in
# the correct order.
#
# Pipeline:
#   1. bootstrap_ghidra_project.sh  — import SCUS, BATTLE.BIN, and
#                                      effect bins (E001..) into Ghidra.
#   2. fix_battle_bin_disassembly.sh — apply BATTLE.BIN-specific fixes
#                                      (force-D missing ranges, add
#                                      BATTLE_SECONDARY overlay at
#                                      base 0x80067000).
#   3. apply_all_renames.sh         — apply the content pipeline (LOW
#                                      and HIGH renames, BATTLE labels,
#                                      JSONL comments) from
#                                      fft-ghidra/content/.
#   4. export_ghidra_text.sh        — regenerate
#                                      project-assets/fft-rom/*.txt
#                                      and *.c.
#
# Run this from a fresh Ghidra project (deleted fft-ghidra.gpr/.rep
# beforehand) to fully reproduce the current state from raw ISO.
#
# Usage:
#   GHIDRA_HOME=/opt/ghidra ./fft-ghidra/tools/rebuild_ghidra_from_iso.sh
#
# Add --listing-only to step 4 if you want to skip decompilation
# (20-40 min for BATTLE.BIN). Default does both listings + decomp.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}
cd "$REPO_ROOT"
TOOLS_DIR="$REPO_ROOT/fft-ghidra/tools"

LISTING_ONLY=""
if [[ "${1:-}" == "--listing-only" ]]; then
  LISTING_ONLY="--listing-only"
fi

echo "=== STEP 1/4: bootstrap_ghidra_project.sh ==="
"$TOOLS_DIR/bootstrap_ghidra_project.sh"

echo ""
echo "=== STEP 2/4: fix_battle_bin_disassembly.sh ==="
"$TOOLS_DIR/fix_battle_bin_disassembly.sh"

echo ""
echo "=== STEP 3/4: apply_all_renames.sh ==="
"$TOOLS_DIR/apply_all_renames.sh"

echo ""
echo "=== STEP 4/4: export_ghidra_text.sh $LISTING_ONLY ==="
"$TOOLS_DIR/export_ghidra_text.sh" $LISTING_ONLY

echo ""
echo "=== rebuild_ghidra_from_iso: done ==="
echo "Disassembly:"
echo "  $REPO_ROOT/project-assets/fft-rom/scus_disassembly.txt"
echo "  $REPO_ROOT/project-assets/fft-rom/battle_disassembly.txt"
echo "Decompilation:"
echo "  $REPO_ROOT/project-assets/fft-rom/scus_decompilation.c"
echo "  $REPO_ROOT/project-assets/fft-rom/battle_decompilation.c"
echo ""
echo "Verify both dumps are present + complete:"
echo "  python3 $REPO_ROOT/fft-ghidra/tests/test_exports_present.py"
