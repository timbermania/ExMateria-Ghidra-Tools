#!/usr/bin/env python3
"""Verify project-assets/fft-rom/battle_disassembly.txt was exported with the
correct load base (0x80067000), not the stale +0x800 base.

Background
----------
PCSX-Redux loads BATTLE.BIN at RAM 0x80067000 (live-verified — file byte 0
appears at RAM 0x80067000). bootstrap_ghidra_project.sh was fixed
2026-06-20 to import at this base. But if export_ghidra_text.sh wasn't
re-run after the bootstrap fix, the resulting battle_disassembly.txt
still has every address +0x800 ahead of real RAM — silently breaking
every cite-by-RAM-address workflow.

Test
----
Read the first 4 bytes of BATTLE.BIN (from the extract dir). They should
appear in battle_disassembly.txt at address `0x80067000` (correct) — NOT
at `0x80067800` (stale).

Fail loudly with the regen instructions if stale.
"""

import sys
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BATTLE_BIN = REPO / "project-assets" / "fft-extract" / "BATTLE.BIN"
DISASM = REPO / "project-assets" / "fft-rom" / "battle_disassembly.txt"

REAL_BASE = 0x80067000
STALE_BASE = 0x80067800


def _first_addr_in_disasm() -> int | None:
    """Return the first RAM address that the disasm shows.

    Ghidra's text export uses one of two prefixes depending on whether the
    binary was imported as a separate program with a block name (`battle:`,
    `scus:`) or as a flat RAM mount (`ram:`). Accept both.
    """
    pat = re.compile(r"(?:ram|battle|scus):([0-9a-fA-F]{8})")
    with DISASM.open("r") as f:
        for line in f:
            m = pat.search(line)
            if m:
                return int(m.group(1), 16)
    return None


def main() -> int:
    if not BATTLE_BIN.exists():
        print(f"SKIP: {BATTLE_BIN} not present "
              f"(populate project-assets/ per SETUP.md)", file=sys.stderr)
        return 0  # not a real failure — extract just isn't here

    if not DISASM.exists():
        print(f"FAIL: {DISASM} missing — run "
              f"`fft-ghidra/tools/export_ghidra_text.sh BATTLE.BIN`",
              file=sys.stderr)
        return 1

    first_addr = _first_addr_in_disasm()
    if first_addr is None:
        print(f"FAIL: no `ram:XXXXXXXX` lines found in {DISASM}", file=sys.stderr)
        return 1

    if first_addr == REAL_BASE:
        print(f"PASS: battle_disassembly.txt mounted at 0x{REAL_BASE:08X} "
              f"(matches PCSX runtime load address)")
        return 0

    if first_addr == STALE_BASE:
        print(
            f"FAIL: battle_disassembly.txt mounted at STALE base "
            f"0x{STALE_BASE:08X} (every address is +0x800 ahead of real RAM).\n\n"
            f"Real PCSX runtime base: 0x{REAL_BASE:08X}.\n"
            f"bootstrap_ghidra_project.sh has the correct base since "
            f"2026-06-20; the export needs to be regenerated:\n\n"
            f"  fft-ghidra/tools/export_ghidra_text.sh BATTLE.BIN\n\n"
            f"(20-40 min decompile.) Until that runs, any RAM address cited\n"
            f"from this file must subtract 0x800 to hit real RAM.",
            file=sys.stderr,
        )
        return 1

    print(
        f"FAIL: battle_disassembly.txt first ram: line shows unexpected "
        f"address 0x{first_addr:08X} (expected 0x{REAL_BASE:08X} or stale "
        f"0x{STALE_BASE:08X}). The export may be from a different mount or "
        f"corrupted — re-run bootstrap + export.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
