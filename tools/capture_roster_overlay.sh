#!/usr/bin/env bash
# capture_roster_overlay.sh — snapshot the live FORMATION/ROSTER menu overlay
# code region from a running pcsx-redux and slice it into the committed .bin
# that ghidra_add_roster_overlay.py mounts.
#
# WHY: the roster/formation "sort list" screen's render code (the glowing orb
# generator @0x80116AEC, spatial falloff @0x80116DD0, per-sprite setter
# @0x8012C8E0, box builder, upload path) is a menu-system OVERLAY that FFT
# DMAs into RAM over BATTLE.BIN at ~0x800F0000-0x80130000. On disc BATTLE.BIN
# is 0x00 there (verified: file offset (VA-0x80067000) reads zeros), so the
# static battle_disassembly.txt cannot see it. This grabs the live bytes so
# Ghidra can disassemble the installed code. See
# research/working_documents/FORMATION_SCREEN.md §10-11 and
# /tmp/HANDOFF_formation_orb_box_evidence.md.
#
# PRECONDITION: pcsx-redux running on the worktree's web port (default 8080)
# WITH the roster screen resident (load SCUS94221.sstate0 — the user quick-save
# captured at the world-map Menu-opening, one resume from the screen). The orb
# code+primitive must be live; this script verifies before writing.
#
# USAGE:
#   fft-ghidra/tools/capture_roster_overlay.sh [PORT]
#
# Output (committed, ~256 KiB):
#   research/captures/roster_menu_overlay_800F0000_256kb.bin
set -euo pipefail

PORT="${1:-8080}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO_ROOT/research/captures/roster_menu_overlay_800F0000_256kb.bin"
BASE=0x800F0000   # RAM base of the mounted overlay block
SIZE=0x40000      # 256 KiB — covers gen/fall/setter + margin

TMP="$(mktemp -t ram_live.XXXXXX.bin)"
trap 'rm -f "$TMP"' EXIT

echo "[capture] GET /api/v1/cpu/ram/raw (port $PORT)"
curl -sf -m 15 "http://localhost:$PORT/api/v1/cpu/ram/raw" -o "$TMP"
sz=$(stat -c%s "$TMP")
[ "$sz" -eq 2097152 ] || { echo "[capture] ERR: RAM dump is $sz bytes, expected 2097152"; exit 1; }

OUT="$OUT" TMP="$TMP" BASE="$BASE" SIZE="$SIZE" python3 - <<'PY'
import os
r = open(os.environ["TMP"], "rb").read()
base = int(os.environ["BASE"], 16); size = int(os.environ["SIZE"], 16)
off = base - 0x80000000
blob = r[off:off + size]

# Verify the overlay is actually resident: the generator @0x80116AEC must be
# real MIPS (`sb v0,0x58(sp)` = 58 00 a2 a3) and the orb primitive @0x801F10D8
# must carry the FRAME-sheet CLUT 0x7F27 / tpage 0x3F / cmd 0x2E.
gen = blob[0x80116AEC - base: 0x80116AEC - base + 4]
if gen != bytes.fromhex("5800a2a3"):
    raise SystemExit(f"[capture] ERR: generator bytes {gen.hex()} != 5800a2a3 — roster overlay NOT resident. "
                     "Load SCUS94221.sstate0 first.")
prim = r[0x1F10D8: 0x1F10D8 + 16]
if prim[7] != 0x2E or prim[12:16] != bytes.fromhex("f349277f"):
    raise SystemExit(f"[capture] ERR: orb primitive @0x801F10D8 not live: {prim.hex(' ')}")

open(os.environ["OUT"], "wb").write(blob)
nz = sum(1 for b in blob if b) / len(blob)
print(f"[capture] wrote {os.environ['OUT']} ({len(blob)} bytes, nonzero={nz:.2f})")
print(f"[capture] orb primitive live: {prim.hex(' ')} (color={prim[4:7].hex()} clut=0x7F27 cmd=0x2E)")
PY
echo "[capture] done — mount with: fft-ghidra/tools/ghidra_add_roster_overlay.py"
