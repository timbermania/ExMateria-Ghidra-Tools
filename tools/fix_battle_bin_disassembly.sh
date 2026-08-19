#!/usr/bin/env bash
# fix_battle_bin_disassembly.sh — apply BATTLE.BIN-specific Ghidra
# post-import fixes to make the disassembly reflect the actual
# runtime memory layout.
#
# As of 2026-06-20, bootstrap_ghidra_project.sh imports BATTLE.BIN at the
# CORRECT base 0x80067000 (live-verified). The "two segments" theory
# below was a misdiagnosis of the off-by-0x800 bootstrap base; with the
# primary block now correct, steps 2-3 (BATTLE_SECONDARY overlay) are
# redundant but harmless — they remap the same data at the same RAM
# address. Step 1 (force-disassemble data-as-code in the primary block)
# is still useful. Plan to retire the secondary-block steps in a future
# cleanup pass.
#
# Historical (kept for context):
# - Ghidra's old default import put everything at base 0x80067800, off
#   from live RAM by 0x800.
# - The "secondary block at RAM 0x801A9800 from file offset 0x142800"
#   was a partial fix: by coincidence,
#       0x80067000 + 0x142800 = 0x801A9800
#   so the secondary block had the correct base for that file region.
#   With primary now at 0x80067000, the same equation holds and the
#   block overlays the existing primary mapping cleanly.
#
# This script applies the fixes via headless Ghidra:
#   1. Force-disassemble the 34 known data ranges in the primary block
#   2. Add an overlay block at RAM 0x801A9800 mapped from file
#      offset 0x142800 (the secondary section) — now redundant
#   3. Force-disassemble every 4-byte boundary in the overlay
#   4. Re-export the disassembly text file
#
# Usage:
#   ./fft-ghidra/tools/fix_battle_bin_disassembly.sh
#
# Idempotent — safe to re-run. Existing BATTLE_SECONDARY overlays get
# removed and re-created.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}
cd "$REPO_ROOT"

GHIDRA_PROJ_DIR="$REPO_ROOT/project-assets"
GHIDRA_PROJ_NAME="fft-ghidra"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
ANALYZE="$GHIDRA_HOME/support/pyghidraRun"

if [[ ! -x "$ANALYZE" ]]; then
  echo "ERROR: pyghidraRun not found at $ANALYZE"
  echo "Set GHIDRA_HOME to point at a Ghidra installation with PyGhidra."
  exit 1
fi

SCRIPT_DIR="$REPO_ROOT/fft-ghidra/tools"

echo "=== fix_battle_bin: step 1 — force-disassemble primary block ranges ==="
echo -e "y\ny" | timeout 600 "$ANALYZE" -H "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
  -process "BATTLE.BIN" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ghidra_force_disassemble_battle.py 2>&1 | \
  grep -E "force_disasm\]|ERROR:" | head -20

echo ""
echo "=== fix_battle_bin: step 2 — add BATTLE_SECONDARY overlay block ==="
echo -e "y\ny" | timeout 600 "$ANALYZE" -H "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
  -process "BATTLE.BIN" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ghidra_add_battle_secondary.py 2>&1 | \
  grep -E "secondary\]|ERROR:" | head -20

echo ""
echo "=== fix_battle_bin: step 3 — disassemble all overlay entries ==="
echo -e "y\ny" | timeout 600 "$ANALYZE" -H "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
  -process "BATTLE.BIN" \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ghidra_disassemble_secondary.py 2>&1 | \
  grep -E "disasm\]|ERROR:" | head -10

echo ""
echo "=== fix_battle_bin: step 4 — import runtime-installed code at 0x80150A00 (if dump available) ==="
# The chan_92 clear at PC 0x80150AEC (see
# research/effect_sound/working_documents/PARITY_AB_VOICE_20_EMULATOR_DIVERGENCE.md)
# lives in a region of BATTLE.BIN's primary address space that is zero
# on disc and patched at runtime by an unknown loader. To disassemble
# the actually-running code, we need a RAM snapshot taken from PCSX-Redux.
# The Lua helper at research/lua_scripts/dump_pc_80150_function.lua
# produces ram_80150A00_4kb.bin; the Ghidra script below imports it
# as an overlay block called BATTLE_INSTALL_80150. Skipped silently if
# the dump file isn't present (the rest of the fix script still runs).
RUNTIME_DUMP_CANONICAL="$REPO_ROOT/research/captures/ram_80150A00_4kb.bin"
RUNTIME_DUMP_FALLBACK="$HOME/.config/pcsx-redux/ram_80150A00_4kb.bin"
if [[ -f "$RUNTIME_DUMP_CANONICAL" || -f "$RUNTIME_DUMP_FALLBACK" ]]; then
  export FFT_REPO_ROOT="$REPO_ROOT"
  echo -e "y\ny" | timeout 600 "$ANALYZE" -H "$GHIDRA_PROJ_DIR" "$GHIDRA_PROJ_NAME" \
    -process "BATTLE.BIN" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript ghidra_add_runtime_install_80150.py 2>&1 | \
    grep -E "install_80150\]|ERROR:" | head -10
else
  echo "  SKIP — no runtime dump at:"
  echo "    $RUNTIME_DUMP_CANONICAL"
  echo "  or $RUNTIME_DUMP_FALLBACK"
  echo "  Capture via PCSX-Redux Lua console:"
  echo "    dofile('$REPO_ROOT/research/lua_scripts/dump_pc_80150_function.lua')"
  echo "  with protect_no_music loaded, then re-run this script."
fi

echo ""
echo "=== fix_battle_bin: step 5 — re-export disassembly ==="
echo -e "y\ny" | timeout 600 "$SCRIPT_DIR/export_ghidra_text.sh" --listing-only BATTLE.BIN 2>&1 | tail -5

echo ""
echo "=== fix_battle_bin: done ==="
echo "Disassembly file: $(stat -c%s $REPO_ROOT/project-assets/fft-rom/battle_disassembly.txt) bytes"
echo ""
echo "Verify:"
echo "  grep 'BATTLE_SECOND'    project-assets/fft-rom/battle_disassembly.txt | grep 'jal' | head -5"
echo "  grep 'BATTLE_INSTALL'   project-assets/fft-rom/battle_disassembly.txt | head -5"
echo "  grep '80150aec'         project-assets/fft-rom/battle_disassembly.txt"
