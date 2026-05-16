#!/usr/bin/env bash
# fix_battle_bin_disassembly.sh — apply BATTLE.BIN-specific Ghidra
# post-import fixes to make the disassembly reflect the actual
# runtime memory layout.
#
# Discovered issues (see CADENCE_DRIFT_SPAWN_DELAY.md and commits
# d31fa1f4, 30506350):
# - BATTLE.BIN has TWO load segments. Ghidra's default import puts
#   everything at base 0x80067800, but the file's tail (offset
#   0x142800..0x155168) actually loads at RAM 0x801A9800+ (base
#   0x80067000). At runtime, RAM 0x801AA000..0x801AA7FF has the
#   secondary content (overlays the primary).
# - Ghidra's auto-analyzer left many ranges in the primary as `??`
#   data instead of disassembling them. Most are real code.
#
# This script applies the fixes via headless Ghidra:
#   1. Force-disassemble the 34 known data ranges in the primary block
#   2. Add an overlay block at RAM 0x801A9800 mapped from file
#      offset 0x142800 (the secondary section)
#   3. Force-disassemble every 4-byte boundary in the overlay
#   4. Re-export the disassembly text file
#
# Usage:
#   ./research/tools/fix_battle_bin_disassembly.sh
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

SCRIPT_DIR="$REPO_ROOT/research/tools"

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
