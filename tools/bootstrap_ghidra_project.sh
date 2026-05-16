#!/usr/bin/env bash
# bootstrap_ghidra_project.sh — create a fresh fft-ghidra Ghidra project at
# project-assets/fft-ghidra/ from extracted ROM binaries, then apply renames.
#
# Idempotent re-creation: refuses to clobber an existing project. To start
# over, delete `project-assets/fft-ghidra.{gpr,rep}` first.
#
# Usage:
#   ./bootstrap_ghidra_project.sh
#   FFT_EXTRACT_DIR=/path/to/iso/tree ./bootstrap_ghidra_project.sh
#   GHIDRA_HOME=/opt/ghidra ./bootstrap_ghidra_project.sh
#
# Expects SCUS_942.21 and BATTLE.BIN somewhere under $FFT_EXTRACT_DIR
# (default: project-assets/fft-extract/). They can live at the top level or
# nested in subdirs — find walks the tree.
#
# Imports both with processor MIPS:LE:32:default. SCUS has a 0x800-byte
# PS-X EXE header that's skipped via -loader-fileOffset. Base addresses:
#   SCUS_942.21   →  0x80010000  (after 0x800 header)
#   BATTLE.BIN    →  0x80067800  (overlay, raw)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "ERROR: not inside a git repo"; exit 1
}

EXTRACT_DIR="${FFT_EXTRACT_DIR:-$REPO_ROOT/project-assets/fft-extract}"
PROJ_DIR="$REPO_ROOT/project-assets"
PROJ_NAME="fft-ghidra"
ANALYZE="${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless"

[[ -x "$ANALYZE" ]] || { echo "ERROR: analyzeHeadless not at $ANALYZE (set GHIDRA_HOME)"; exit 1; }

SCUS="$(find "$EXTRACT_DIR" -name 'SCUS_942.21' -type f -print -quit 2>/dev/null || true)"
BATTLE="$(find "$EXTRACT_DIR" -name 'BATTLE.BIN' -type f -print -quit 2>/dev/null || true)"

[[ -f "${SCUS:-}"   ]] || { echo "ERROR: SCUS_942.21 not found under $EXTRACT_DIR"; exit 1; }
[[ -f "${BATTLE:-}" ]] || { echo "ERROR: BATTLE.BIN not found under $EXTRACT_DIR"; exit 1; }

if [[ -e "$PROJ_DIR/$PROJ_NAME.gpr" || -d "$PROJ_DIR/$PROJ_NAME.rep" ]]; then
  echo "ERROR: project already exists at $PROJ_DIR/$PROJ_NAME{.gpr,.rep}"
  echo "       rm -rf $PROJ_DIR/$PROJ_NAME.{gpr,rep} to start over"
  exit 1
fi

mkdir -p "$PROJ_DIR"

echo ">>> Bootstrapping $PROJ_DIR/$PROJ_NAME"
echo "    SCUS:   $SCUS"
echo "    BATTLE: $BATTLE"

# 1. SCUS_942.21 (PSX-EXE: skip 0x800 header, load body at 0x80010000)
"$ANALYZE" "$PROJ_DIR" "$PROJ_NAME" \
  -import "$SCUS" \
  -loader BinaryLoader \
  -loader-baseAddr 0x80010000 \
  -loader-fileOffset 0x800 \
  -loader-blockName scus \
  -processor "MIPS:LE:32:default"

# 2. BATTLE.BIN (raw overlay, loads at 0x80067800)
"$ANALYZE" "$PROJ_DIR" "$PROJ_NAME" \
  -import "$BATTLE" \
  -loader BinaryLoader \
  -loader-baseAddr 0x80067800 \
  -loader-blockName battle \
  -processor "MIPS:LE:32:default"

# 3. Apply renames from fft-ghidra/renames/*.tsv. Best-effort: project is
#    still usable if this fails (just FUN_xxxxxxxx everywhere).
if [[ -x "$REPO_ROOT/fft-ghidra/tools/apply_all_renames.sh" ]]; then
  echo ">>> Applying renames..."
  "$REPO_ROOT/fft-ghidra/tools/apply_all_renames.sh" SCUS_942.21 BATTLE.BIN || {
    echo "WARN: apply_all_renames.sh failed; project usable but unnamed."
  }
fi

echo
echo "✓ Ghidra project ready at $PROJ_DIR/$PROJ_NAME"
echo "  - Open with Ghidra GUI: File → Open Project → $PROJ_DIR/$PROJ_NAME.gpr"
echo "  - Refresh exports:      fft-ghidra/tools/export_ghidra_text.sh"
